//! Frame generation for full-system fuzzing: valid seed frames of every
//! kind the kernel parses, and mutations that keep most of a frame valid
//! so deeper code paths are reached.

use crate::frame::{self, HOST_IP, KERNEL_IP};
use rand::Rng;
use rand::seq::SliceRandom;
use sec_core::config::{MANAGEMENT_PORT, TELEMETRY_PORT};
use sec_core::security::mgmt::ManagementMessageType;

/// Largest frame the kernel's RX buffers hold (1536 minus the VirtIO header).
pub const MAX_FRAME: usize = 1526;

/// Header offsets mutations aim at: Ethernet type, IPv4 version/IHL, total
/// length, protocol, addresses, ports, TCP data offset and flags.
const INTERESTING_OFFSETS: [usize; 12] = [12, 13, 14, 16, 17, 23, 26, 30, 36, 37, 46, 47];

/// A source address the generator picks, biased toward a few so the
/// heavy-hitter and flow paths see repeat sources.
fn src_ip(rng: &mut impl Rng) -> [u8; 4] {
    if rng.gen_bool(0.5) {
        [10, 0, 0, rng.gen_range(1..8)]
    } else {
        [rng.r#gen(), rng.r#gen(), rng.r#gen(), rng.r#gen()]
    }
}

fn tcp_segment(rng: &mut impl Rng) -> Vec<u8> {
    let mut l4 = vec![0u8; 20];
    l4[0..2].copy_from_slice(&rng.r#gen::<u16>().to_be_bytes());
    let dst_port: u16 = *[22u16, 23, 80, 443, MANAGEMENT_PORT, rng.r#gen()]
        .choose(rng)
        .unwrap_or(&80);
    l4[2..4].copy_from_slice(&dst_port.to_be_bytes());
    l4[4..8].copy_from_slice(&rng.r#gen::<u32>().to_be_bytes());
    l4[12] = 0x50;
    l4[13] = *[0x02u8, 0x10, 0x18, 0x29, 0x00, 0x12, rng.r#gen()]
        .choose(rng)
        .unwrap_or(&0x02);
    l4.extend_from_slice(&payload(rng));
    l4
}

fn payload(rng: &mut impl Rng) -> Vec<u8> {
    let interesting: [&[u8]; 6] = [
        b"GET / HTTP/1.1",
        b"x UNION SELECT 1",
        b"<script>alert(1)</script>",
        &[0x90; 16],
        &[0x13, 0, 0, 0, 0x13, 0, 0, 0, 0x13, 0, 0, 0, 0x13, 0, 0, 0],
        b"",
    ];
    let mut bytes = interesting
        .choose(rng)
        .map_or_else(Vec::new, |p| p.to_vec());
    let extra = rng.gen_range(0..64);
    bytes.extend((0..extra).map(|_| rng.r#gen::<u8>()));
    bytes
}

/// A well-formed frame of a random kind the kernel parses.
pub fn seed_frame(rng: &mut impl Rng) -> Vec<u8> {
    match rng.gen_range(0..5) {
        0 => frame::arp_request(if rng.gen_bool(0.8) {
            KERNEL_IP
        } else {
            src_ip(rng)
        }),
        1 => {
            let mut l4 = vec![8, 0, 0, 0, 0, 1, 0, 1];
            l4.extend_from_slice(&payload(rng));
            frame::ipv4_to_kernel(src_ip(rng), 1, &l4)
        }
        2 => frame::ipv4_to_kernel(src_ip(rng), 6, &tcp_segment(rng)),
        3 => {
            let dst = *[
                53u16,
                80,
                8888,
                TELEMETRY_PORT,
                MANAGEMENT_PORT,
                rng.r#gen(),
            ]
            .choose(rng)
            .unwrap_or(&53);
            frame::udp_to_kernel(src_ip(rng), rng.r#gen(), dst, &payload(rng))
        }
        _ => {
            let mut body = vec![rng.gen_range(0..=9u8)];
            body.extend((0..rng.gen_range(0..32)).map(|_| rng.r#gen::<u8>()));
            frame::udp_to_kernel(HOST_IP, rng.r#gen(), MANAGEMENT_PORT, &body)
        }
    }
}

/// A random, plausibly well-formed mgmt command body.
pub fn mgmt_body(rng: &mut impl Rng) -> Vec<u8> {
    let kinds = [
        ManagementMessageType::BlockPort,
        ManagementMessageType::AddDpiPattern,
        ManagementMessageType::UploadBpfProgram,
        ManagementMessageType::BanIp,
        ManagementMessageType::UnblockPort,
        ManagementMessageType::RemoveDpiPattern,
        ManagementMessageType::UnloadBpfProgram,
        ManagementMessageType::UnbanIp,
    ];
    let kind = *kinds
        .choose(rng)
        .unwrap_or(&ManagementMessageType::BlockPort);
    let mut body = vec![kind as u8];
    match kind {
        ManagementMessageType::BlockPort | ManagementMessageType::UnblockPort => {
            body.extend_from_slice(&rng.r#gen::<u16>().to_be_bytes());
        }
        ManagementMessageType::BanIp | ManagementMessageType::UnbanIp => {
            body.extend_from_slice(&src_ip(rng));
        }
        ManagementMessageType::AddDpiPattern | ManagementMessageType::RemoveDpiPattern => {
            let pattern = payload(rng);
            let len = pattern.len().min(40);
            body.push(u8::try_from(len).unwrap_or(u8::MAX));
            body.extend_from_slice(&pattern[..len]);
        }
        ManagementMessageType::UnloadBpfProgram => {}
        ManagementMessageType::UploadBpfProgram => {
            let count = rng.gen_range(0..=12u8);
            body.push(count);
            for _ in 0..count {
                body.push(rng.gen_range(0..=0x0E));
                body.push(rng.gen_range(0..18));
                body.push(rng.gen_range(0..18));
                let imm: u32 = if rng.gen_bool(0.7) {
                    rng.gen_range(0..64)
                } else {
                    rng.r#gen()
                };
                body.extend_from_slice(&imm.to_be_bytes());
            }
        }
    }
    if rng.gen_bool(0.1) {
        let cut = rng.gen_range(1..=body.len());
        body.truncate(cut);
    }
    body
}

/// Applies a few random mutations, keeping the frame non-empty and within
/// what the NIC can deliver.
pub fn mutate(frame: &mut Vec<u8>, rng: &mut impl Rng) {
    for _ in 0..rng.gen_range(1..=4) {
        match rng.gen_range(0..6) {
            0 => {
                if let Some(&offset) = INTERESTING_OFFSETS.choose(rng)
                    && let Some(byte) = frame.get_mut(offset)
                {
                    *byte = *[
                        0x00u8,
                        0x01,
                        0x05,
                        0x0F,
                        0x40,
                        0x45,
                        0x4F,
                        0x7F,
                        0x80,
                        0xFF,
                        rng.r#gen(),
                    ]
                    .choose(rng)
                    .unwrap_or(&0);
                }
            }
            1 => {
                let i = rng.gen_range(0..frame.len());
                frame[i] ^= 1 << rng.gen_range(0..8);
            }
            2 => {
                let i = rng.gen_range(0..frame.len());
                frame[i] = rng.r#gen();
            }
            3 => {
                let len = rng.gen_range(1..=frame.len());
                frame.truncate(len);
            }
            4 => {
                let extra = rng.gen_range(1..=64);
                frame.extend((0..extra).map(|_| rng.r#gen::<u8>()));
            }
            _ => {
                let (a, b) = (rng.gen_range(0..frame.len()), rng.gen_range(0..frame.len()));
                frame.swap(a, b);
            }
        }
    }
    frame.truncate(MAX_FRAME);
    if frame.is_empty() {
        frame.push(0);
    }
}
