#![no_main]
//! Fuzz one frame through the full engine pipeline.
//!
//! Beyond "never panics", checks that every frame lands in at most one
//! interval counter and that the counter matches the verdict, and that the
//! engine never emits a frame larger than the NIC can carry.

use libfuzzer_sys::fuzz_target;
use sec_core::engine::{BootSecrets, Engine, IntervalStats, Verdict};
use sec_core::net::PacketSink;
use sec_core::net::stack::SynCookieSecret;
use sec_core::security::alert::AlertReason;

/// Largest Ethernet frame (without FCS) the VirtIO TX path accepts.
const MAX_FRAME: usize = 1526;

struct CheckedSink;

impl PacketSink for CheckedSink {
    fn send(&mut self, frame: &[u8]) {
        assert!(frame.len() <= MAX_FRAME, "emitted {}-byte frame", frame.len());
        assert!(frame.len() >= 14, "emitted runt frame of {} bytes", frame.len());
    }
}

fn counters(s: &IntervalStats) -> [u64; 7] {
    [s.passed, s.ddos, s.firewall, s.malware, s.ebpf, s.heuristic, s.mgmt]
}

fn expected_counter(verdict: Verdict) -> Option<usize> {
    match verdict {
        Verdict::Passed => Some(0),
        Verdict::Dropped(AlertReason::Ddos) => Some(1),
        Verdict::Dropped(AlertReason::Firewall) => Some(2),
        Verdict::Dropped(AlertReason::Malware) => Some(3),
        Verdict::Dropped(
            AlertReason::Ebpf | AlertReason::BpfTimeout | AlertReason::BpfInvalidAction,
        ) => Some(4),
        Verdict::Dropped(AlertReason::Heuristic) => Some(5),
        Verdict::Management => Some(6),
        Verdict::Consumed => None,
        Verdict::Dropped(other) => panic!("unexpected drop reason {other:?}"),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_FRAME {
        return;
    }
    let mut engine: Engine = Engine::new([0x5A; 16]);
    engine.init(BootSecrets {
        syn_cookie: SynCookieSecret::new([0x42; 16]),
        cms_key: [1; 16],
        mgmt_epoch: 1,
    });
    let before = counters(engine.interval_stats());
    let mut frame = data.to_vec();

    let verdict = engine.process(&mut frame, 1, &mut CheckedSink);

    let after = counters(engine.interval_stats());
    let changed: Vec<usize> = (0..before.len()).filter(|&i| after[i] != before[i]).collect();
    match expected_counter(verdict) {
        Some(i) => assert_eq!(changed, [i], "{verdict:?} moved counters {changed:?}"),
        None => assert!(changed.is_empty(), "{verdict:?} moved counters {changed:?}"),
    }
});
