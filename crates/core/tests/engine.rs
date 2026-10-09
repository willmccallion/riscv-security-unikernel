//! Behaviour of the full per-packet pipeline in `sec_core::engine`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{CaptureSink, PEER_IP, engine, mgmt, tcp, udp};
use sec_core::config::DEFAULT_BLOCKED_PORT;
use sec_core::engine::Verdict;
use sec_core::security::alert::AlertReason;
use sec_core::security::mgmt::ManagementMessageType;

#[test]
fn clean_udp_passes() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    let v = e.process(&mut udp(PEER_IP, 5000, 80, b"GET / HTTP/1.1"), 1, &mut sink);

    assert_eq!(v, Verdict::Passed);
    assert_eq!(e.interval_stats().passed, 1);
}

#[test]
fn traffic_to_blocked_port_is_dropped_with_firewall_alert() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    let v = e.process(&mut udp(PEER_IP, 5000, DEFAULT_BLOCKED_PORT, b"hello"), 1, &mut sink);

    assert_eq!(v, Verdict::Dropped(AlertReason::Firewall));
    assert!(sink.alert_reasons().contains(&AlertReason::Firewall));
}

#[test]
fn signature_match_is_dropped_as_malware() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    let v = e.process(&mut udp(PEER_IP, 5000, 80, b"x UNION SELECT 1"), 1, &mut sink);

    assert_eq!(v, Verdict::Dropped(AlertReason::Malware));
}

#[test]
fn xmas_scan_is_dropped_by_heuristics() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    let v = e.process(&mut tcp(PEER_IP, 5000, 80, 0x29, b""), 1, &mut sink);

    assert_eq!(v, Verdict::Dropped(AlertReason::Heuristic));
}

#[test]
fn heavy_hitter_is_banned_after_threshold() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut last = Verdict::Passed;

    for i in 0..200u64 {
        last = e.process(&mut udp([10, 0, 0, 9], 5000, 80, b"flood"), i * 1_000_000, &mut sink);
    }

    assert_eq!(last, Verdict::Dropped(AlertReason::Ddos));
}

#[test]
fn unsigned_mgmt_packet_raises_auth_failure() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    let v = e.process(
        &mut udp(PEER_IP, 40_000, sec_core::config::MANAGEMENT_PORT, &[0u8; 24]),
        1,
        &mut sink,
    );

    assert_eq!(v, Verdict::Management);
    assert!(sink.alert_reasons().contains(&AlertReason::MgmtAuthFail));
}

#[test]
fn authenticated_block_port_takes_effect() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let body = [ManagementMessageType::BlockPort as u8, 0x1F, 0x90];
    let _ = e.process(&mut mgmt(1, &body), 1, &mut sink);

    let v = e.process(&mut udp(PEER_IP, 5000, 8080, b"hello"), 2, &mut sink);

    assert_eq!(v, Verdict::Dropped(AlertReason::Firewall));
}

#[test]
fn alerts_go_to_the_operator_after_it_authenticates() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let _ = e.process(&mut mgmt(1, &[ManagementMessageType::BlockPort as u8, 0, 99]), 1, &mut sink);
    sink.sent.clear();

    let _ = e.process(&mut udp(PEER_IP, 5000, 99, b"x"), 2, &mut sink);

    let alert = sink.sent.last().expect("firewall alert");
    assert_eq!(&alert[0..6], &common::PEER_MAC);
    assert_eq!(&alert[30..34], &PEER_IP);
}

#[test]
fn icmp_echo_is_answered_even_when_its_checksum_equals_a_blocked_port() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    let v = e.process(
        &mut common::icmp_echo(PEER_IP, DEFAULT_BLOCKED_PORT),
        1,
        &mut sink,
    );

    assert_eq!(v, Verdict::Consumed);
    assert!(sink.alert_reasons().is_empty());
}

#[test]
fn banned_source_does_not_create_flows() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let attacker = [10, 0, 0, 66];
    for i in 0..150u64 {
        let _ = e.process(&mut udp(attacker, 5000, 80, b"flood"), i * 1_000_000, &mut sink);
    }
    let flows_when_banned = e.active_flows();

    for port in 0..50u16 {
        let _ = e.process(&mut udp(attacker, 6000 + port, 80, b"x"), 200_000_000, &mut sink);
    }

    assert_eq!(e.active_flows(), flows_when_banned);
}

#[test]
fn telemetry_is_a_signed_report_carrying_the_epoch() {
    use sec_core::security::report_auth::telemetry_packet;
    let mut e = engine();
    let mut sink = CaptureSink::default();

    e.send_telemetry(1234, &mut sink);

    let body = &sink.report_bodies()[0];
    assert_eq!(body[0], telemetry_packet::MESSAGE_TYPE);
    let epoch_slot = telemetry_packet::SLOTS_OFFSET + 9 * 8;
    let epoch = u64::from_be_bytes(body[epoch_slot..epoch_slot + 8].try_into().unwrap());
    assert_eq!(epoch, u64::from(common::EPOCH));
}

#[test]
fn a_flood_of_blocked_traffic_raises_a_bounded_number_of_alerts() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    for i in 0..500u16 {
        let src = [10, 3, (i >> 8) as u8, i as u8];
        let _ = e.process(&mut udp(src, 5000, DEFAULT_BLOCKED_PORT, b"x"), u64::from(i), &mut sink);
    }

    assert_eq!(e.interval_stats().firewall, 50, "the global rate limit admits 50");
    assert!(sink.alert_reasons().len() <= 32, "{} alerts", sink.alert_reasons().len());
}

#[test]
fn a_burst_straddling_a_decay_is_still_caught() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let attacker = [10, 0, 0, 77];
    let mut now = 0;
    let mut send_burst = |e: &mut sec_core::engine::Engine, now: &mut u64| {
        let mut last = Verdict::Passed;
        for _ in 0..90 {
            *now += 1_000_000;
            last = e.process(&mut udp(attacker, 5000, 80, b"burst"), *now, &mut sink);
        }
        last
    };

    let first = send_burst(&mut e, &mut now);
    e.end_detection_interval(now, &mut CaptureSink::default());
    let second = send_burst(&mut e, &mut now);

    assert_eq!(first, Verdict::Passed, "90 packets alone stay under the threshold");
    assert_eq!(second, Verdict::Dropped(AlertReason::Ddos));
}
