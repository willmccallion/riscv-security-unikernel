//! Synthetic traffic for benchmarks and the flood generator.

use rand::Rng;
use rand::rngs::StdRng;
use sec_core::config::{DEFAULT_BLOCKED_PORT, IP_ADDR, MAC_ADDR};
use sec_core::net::stack::checksum;

/// What kind of traffic to generate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Mix {
    /// Benign UDP and TCP from many sources.
    Clean,
    /// Signature matches, scans, NOP sleds and blocked ports.
    Attack,
    /// Mostly clean with a tenth attack traffic.
    Mixed,
}

/// Distinct source addresses clean traffic is spread over.
const SOURCES: u16 = 4096;
const PEER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];

/// Builds `count` frames addressed to the engine.
pub fn frames(mix: Mix, count: usize, rng: &mut StdRng) -> Vec<Vec<u8>> {
    (0..count)
        .map(|_| match mix {
            Mix::Clean => clean(rng),
            Mix::Attack => attack(rng),
            Mix::Mixed if rng.gen_ratio(1, 10) => attack(rng),
            Mix::Mixed => clean(rng),
        })
        .collect()
}

fn clean_source(rng: &mut StdRng) -> [u8; 4] {
    let n = rng.gen_range(0..SOURCES);
    [10, 1, (n >> 8) as u8, (n & 0xFF) as u8]
}

fn http_payload(rng: &mut StdRng) -> Vec<u8> {
    let mut payload = b"GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec();
    let body = rng.gen_range(0..400);
    payload.extend((0..body).map(|_| rng.gen_range(b'a'..=b'z')));
    payload
}

fn clean(rng: &mut StdRng) -> Vec<u8> {
    let src = clean_source(rng);
    let src_port = rng.gen_range(1024..65535);
    if rng.gen_bool(0.5) {
        udp(src, src_port, 80, &http_payload(rng))
    } else {
        tcp(src, src_port, 80, 0x18, &http_payload(rng))
    }
}

fn attack(rng: &mut StdRng) -> Vec<u8> {
    let src = [203, 0, 113, rng.gen_range(1..32)];
    let src_port = rng.gen_range(1024..65535);
    match rng.gen_range(0..5) {
        0 => udp(src, src_port, 80, b"id=1 UNION SELECT password FROM users"),
        1 => tcp(src, src_port, 80, 0x18, b"<script>alert(document.cookie)</script>"),
        2 => tcp(src, src_port, rng.gen_range(1..1024), 0x29, b""),
        3 => udp(src, src_port, 80, &[0x90; 64]),
        _ => udp(src, src_port, DEFAULT_BLOCKED_PORT, b"login"),
    }
}

/// An Ethernet + IPv4 frame from `src` to the engine's address.
pub fn ipv4(src: [u8; 4], protocol: u8, l4: &[u8]) -> Vec<u8> {
    let total = u16::try_from(20 + l4.len()).unwrap_or(u16::MAX);
    let mut f = Vec::with_capacity(34 + l4.len());
    f.extend_from_slice(&MAC_ADDR);
    f.extend_from_slice(&PEER_MAC);
    f.extend_from_slice(&[0x08, 0x00, 0x45, 0x00]);
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
    f.extend_from_slice(&src);
    f.extend_from_slice(&IP_ADDR);
    let csum = checksum(&f[14..34]);
    f[24..26].copy_from_slice(&csum.to_be_bytes());
    f.extend_from_slice(l4);
    f
}

/// A UDP datagram from `src:src_port` to the engine's `dst_port`.
pub fn udp(src: [u8; 4], src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    let mut l4 = Vec::with_capacity(8 + payload.len());
    l4.extend_from_slice(&src_port.to_be_bytes());
    l4.extend_from_slice(&dst_port.to_be_bytes());
    l4.extend_from_slice(&len.to_be_bytes());
    l4.extend_from_slice(&[0, 0]);
    l4.extend_from_slice(payload);
    ipv4(src, 17, &l4)
}

fn tcp(src: [u8; 4], src_port: u16, dst_port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut l4 = vec![0u8; 20];
    l4[0..2].copy_from_slice(&src_port.to_be_bytes());
    l4[2..4].copy_from_slice(&dst_port.to_be_bytes());
    l4[12] = 0x50;
    l4[13] = flags;
    l4.extend_from_slice(payload);
    ipv4(src, 6, &l4)
}
