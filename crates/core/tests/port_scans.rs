//! Port-scan detection through the whole engine.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{CaptureSink, engine, tcp};
use sec_core::config::{PORT_SCAN_CONFIRM_PORTS, PORT_SCAN_WINDOW_INTERVALS};
use sec_core::engine::Verdict;
use sec_core::security::alert::AlertReason;

const SYN: u8 = 0x02;
const SYN_ACK: u8 = 0x12;
const ACK: u8 = 0x10;

/// Packets per detection interval, well under the per-source heavy-hitter
/// threshold, so only the scan detector can ban the prober.
const PROBES_PER_INTERVAL: usize = 40;

/// Sends one packet with `flags` to each of `ports`, from one source.
fn probe_ports(flags: u8, ports: std::ops::Range<u16>) -> (Vec<Verdict>, CaptureSink) {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut verdicts = Vec::new();
    for (i, port) in ports.enumerate() {
        let now = i as u64 * 1_000_000;
        verdicts.push(e.process(&mut tcp([10, 3, 3, 3], 40_000, port, flags, b""), now, &mut sink));
        if (i + 1) % PROBES_PER_INTERVAL == 0 {
            e.end_detection_interval(&mut sink);
        }
    }
    (verdicts, sink)
}

#[test]
fn a_syn_scan_is_banned_and_reported() {
    let (verdicts, sink) = probe_ports(SYN, 1..300);

    let reasons = sink.alert_reasons();
    let scan = reasons.iter().position(|&r| r == AlertReason::PortScan);
    let first_ddos = reasons.iter().position(|&r| r == AlertReason::Ddos);
    assert_eq!(verdicts.last(), Some(&Verdict::Dropped(AlertReason::Ddos)));
    assert!(scan.is_some(), "no port-scan alert");
    assert!(scan < first_ddos, "the scan detector, not the rate detector, banned the prober");
}

#[test]
fn replies_to_many_client_ports_are_not_a_scan() {
    let (syn_acks, syn_ack_sink) = probe_ports(SYN_ACK, 30_000..30_400);
    let (acks, ack_sink) = probe_ports(ACK, 30_000..30_400);

    assert!(syn_acks.iter().chain(&acks).all(|v| *v != Verdict::Dropped(AlertReason::Ddos)));
    assert!(!syn_ack_sink.alert_reasons().contains(&AlertReason::PortScan));
    assert!(!ack_sink.alert_reasons().contains(&AlertReason::PortScan));
}

#[test]
fn a_scan_slower_than_the_window_is_not_caught() {
    const PORTS_PER_WINDOW: u16 = 30;
    let mut e = engine();
    let mut sink = CaptureSink::default();

    for window in 0..12u16 {
        for offset in 1..=PORTS_PER_WINDOW {
            let port = window * PORTS_PER_WINDOW + offset;
            let now = u64::from(port) * 1_000_000;
            let _ = e.process(&mut tcp([10, 3, 3, 3], 40_000, port, SYN, b""), now, &mut sink);
        }
        for _ in 0..PORT_SCAN_WINDOW_INTERVALS {
            e.end_detection_interval(&mut sink);
        }
    }

    assert!(usize::from(PORTS_PER_WINDOW) < PORT_SCAN_CONFIRM_PORTS);
    assert!(!sink.alert_reasons().contains(&AlertReason::PortScan));
}
