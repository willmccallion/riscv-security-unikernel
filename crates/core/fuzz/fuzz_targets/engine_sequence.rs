#![no_main]
//! Fuzz long-lived engine state with sequences of frames, sealed mgmt
//! commands and clock advances.
//!
//! Mgmt commands are sealed with the engine's real key so the fuzzer
//! reaches the dispatcher and can install BPF programs, rules and bans,
//! then probe how later traffic is treated under that state.
//!
//! After every sequence, once the mgmt rate limit has had time to refill,
//! a fresh command from the operator must be acknowledged: no state the
//! fuzzer can build may lock the operator out.

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use sec_core::config::MANAGEMENT_PORT;
use sec_core::engine::{BootSecrets, Engine};
use sec_core::net::PacketSink;
use sec_core::net::stack::SynCookieSecret;
use sec_core::config::{MGMT_BUCKET_CAPACITY, MGMT_TOKEN_COST_CYCLES};
use sec_core::security::mgmt::ack_packet;
use sec_core::security::mgmt::ManagementMessageType;
use sec_core::security::mgmt_auth::seal;
use sec_core::security::report_auth::{ReportVerifier, report_key};

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
    /// Telemetry tick: prune flows, decay the sketch, start a new interval.
    Tick { dt: u32 },
}

/// Checks every emitted frame and records the sequence of each ack.
struct CheckedSink {
    reports: ReportVerifier,
    acked_seqs: Vec<u32>,
}

impl CheckedSink {
    fn new() -> Self {
        Self {
            reports: ReportVerifier::new(report_key(&KEY)),
            acked_seqs: Vec::new(),
        }
    }
}

impl PacketSink for CheckedSink {
    fn send(&mut self, frame: &[u8]) {
        assert!((14..=MAX_FRAME).contains(&frame.len()), "emitted {}-byte frame", frame.len());
        // Replies to the fuzzed frames themselves are not reports.
        let is_report = frame.len() > 42
            && frame[23] == 17
            && frame[26..30] == sec_core::config::IP_ADDR
            && frame[36..38] == sec_core::config::TELEMETRY_PORT.to_be_bytes();
        if !is_report {
            return;
        }
        let report = self.reports.verify(&frame[42..]).expect("report verifies in sequence");
        if let Some(body) = report.body.get(..ack_packet::ACK_BODY_LEN)
            && body[0] == ack_packet::ACK_MESSAGE_TYPE
        {
            let seq = &body[ack_packet::SEQ_OFFSET..ack_packet::SEQ_OFFSET + 4];
            self.acked_seqs.push(u32::from_be_bytes([seq[0], seq[1], seq[2], seq[3]]));
        }
    }
}

fn sealed_mgmt_frame(seq: u32, body: &[u8]) -> Option<Vec<u8>> {
    let counter = (u64::from(EPOCH) << 32) | u64::from(seq);
    let mut sealed = vec![0u8; 16 + body.len()];
    let n = seal(&KEY, counter, body, &mut sealed)?;
    Some(udp_frame(OPERATOR_IP, 40_000, MANAGEMENT_PORT, &sealed[..n]))
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
    let mut engine: Engine = Engine::new(KEY);
    engine.init(BootSecrets {
        syn_cookie: SynCookieSecret::new([0x42; 16]),
        cms_key: [1; 16],
        mgmt_epoch: EPOCH,
    });
    let mut now: u64 = 0;
    let mut seq: u32 = 0;
    let mut sink = CheckedSink::new();

    for step in steps.into_iter().take(256) {
        match step {
            Step::Frame { dt, bytes } => {
                now += u64::from(dt);
                if bytes.len() <= MAX_FRAME {
                    let mut frame = bytes;
                    let _ = engine.process(&mut frame, now, &mut sink);
                }
            }
            Step::Udp { dt, src_last, src_port, dst_port, payload } => {
                now += u64::from(dt);
                if payload.len() <= MAX_FRAME - 42 {
                    let src_ip = [192, 168, 100, src_last];
                    let mut frame = udp_frame(src_ip, src_port, dst_port, &payload);
                    let _ = engine.process(&mut frame, now, &mut sink);
                }
            }
            Step::Mgmt { dt, seq_gap, body } => {
                now += u64::from(dt);
                seq = seq.saturating_add(u32::from(seq_gap));
                if body.len() <= 1400
                    && let Some(mut frame) = sealed_mgmt_frame(seq, &body)
                {
                    let _ = engine.process(&mut frame, now, &mut sink);
                }
            }
            Step::Tick { dt } => {
                now += u64::from(dt);
                engine.prune_flows(now, sec_core::config::FLOW_TIMEOUT_CYCLES as u64);
                engine.end_detection_interval(&mut sink);
                engine.send_telemetry(0, &mut sink);
                engine.start_interval();
            }
        }
    }

    // The verifier only accepts strictly increasing sequences, so a
    // sequence space the fuzzer has exhausted cannot carry a new command.
    let Some(probe_seq) = seq.checked_add(1) else {
        return;
    };
    let refill = MGMT_BUCKET_CAPACITY * MGMT_TOKEN_COST_CYCLES;
    let body = [ManagementMessageType::BanIp as u8, 10, 0, 0, 1];
    let mut probe = sealed_mgmt_frame(probe_seq, &body).expect("probe fits");
    sink.acked_seqs.clear();
    let _ = engine.process(&mut probe, now + refill, &mut sink);
    assert_eq!(sink.acked_seqs, [probe_seq], "operator command was not acknowledged");
});
