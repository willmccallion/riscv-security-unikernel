#![no_main]
//! Fuzz long-lived engine state with sequences of frames, sealed mgmt
//! commands and clock advances.
//!
//! Mgmt commands are sealed with the engine's real key so the fuzzer
//! reaches the dispatcher and can install BPF programs, rules and bans,
//! then probe how later traffic is treated under that state.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use sec_core::config::MANAGEMENT_PORT;
use sec_core::engine::{BootSecrets, Engine};
use sec_core::net::PacketSink;
use sec_core::net::stack::SynCookieSecret;
use sec_core::security::mgmt_auth::seal;

const KEY: [u8; 16] = [0x5A; 16];
const EPOCH: u32 = 7;
const MAX_FRAME: usize = 1526;
const OPERATOR_IP: [u8; 4] = [192, 168, 100, 1];

#[derive(Debug, Arbitrary)]
enum Step {
    /// A raw frame, delivered `dt` cycles after the previous step.
    Frame { dt: u32, bytes: Vec<u8> },
    /// A UDP datagram from `src_last` to `dst_port` carrying `payload`.
    Udp { dt: u32, src_last: u8, src_port: u16, dst_port: u16, payload: Vec<u8> },
    /// A sealed mgmt command; `seq_gap` lets the fuzzer try replays (0).
    Mgmt { dt: u32, seq_gap: u8, body: Vec<u8> },
    /// Telemetry tick: prune flows and start a new interval.
    Tick { dt: u32 },
}

struct CheckedSink;

impl PacketSink for CheckedSink {
    fn send(&mut self, frame: &[u8]) {
        assert!((14..=MAX_FRAME).contains(&frame.len()), "emitted {}-byte frame", frame.len());
    }
}

fn udp_frame(src_ip: [u8; 4], src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 42];
    f[0..6].copy_from_slice(&sec_core::config::MAC_ADDR);
    f[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    f[12..14].copy_from_slice(&[0x08, 0x00]);
    f[14] = 0x45;
    f[16..18].copy_from_slice(&((28 + payload.len()) as u16).to_be_bytes());
    f[22] = 64;
    f[23] = 17;
    f[26..30].copy_from_slice(&src_ip);
    f[30..34].copy_from_slice(&sec_core::config::IP_ADDR);
    f[34..36].copy_from_slice(&src_port.to_be_bytes());
    f[36..38].copy_from_slice(&dst_port.to_be_bytes());
    f[38..40].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fuzz_target!(|steps: Vec<Step>| {
    let mut engine = Engine::new(KEY);
    engine.init(BootSecrets {
        syn_cookie: SynCookieSecret::new([0x42; 16]),
        cms_seed: 1,
        mgmt_epoch: EPOCH,
    });
    let mut now: u64 = 0;
    let mut seq: u32 = 0;

    for step in steps.into_iter().take(256) {
        match step {
            Step::Frame { dt, bytes } => {
                now += u64::from(dt);
                if bytes.len() <= MAX_FRAME {
                    let mut frame = bytes;
                    let _ = engine.process(&mut frame, now, &mut CheckedSink);
                }
            }
            Step::Udp { dt, src_last, src_port, dst_port, payload } => {
                now += u64::from(dt);
                if payload.len() <= MAX_FRAME - 42 {
                    let src_ip = [192, 168, 100, src_last];
                    let mut frame = udp_frame(src_ip, src_port, dst_port, &payload);
                    let _ = engine.process(&mut frame, now, &mut CheckedSink);
                }
            }
            Step::Mgmt { dt, seq_gap, body } => {
                now += u64::from(dt);
                seq = seq.saturating_add(u32::from(seq_gap));
                if body.len() <= 1400 {
                    let counter = (u64::from(EPOCH) << 32) | u64::from(seq);
                    let mut sealed = vec![0u8; 16 + body.len()];
                    if let Some(n) = seal(&KEY, counter, &body, &mut sealed) {
                        let mut frame =
                            udp_frame(OPERATOR_IP, 40_000, MANAGEMENT_PORT, &sealed[..n]);
                        let _ = engine.process(&mut frame, now, &mut CheckedSink);
                    }
                }
            }
            Step::Tick { dt } => {
                now += u64::from(dt);
                engine.prune_flows(now, sec_core::config::FLOW_TIMEOUT_CYCLES as u64);
                engine.send_telemetry(0, &mut CheckedSink);
                engine.start_interval();
            }
        }
    }
});
