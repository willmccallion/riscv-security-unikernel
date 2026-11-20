//! Behaviour of the full per-packet pipeline in `sec_core::engine`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{CaptureSink, PEER_IP, engine, ipv4, mgmt, tcp, udp};
use sec_core::config::DEFAULT_BLOCKED_PORT;
use sec_core::engine::Verdict;
use sec_core::security::alert::AlertReason;
use sec_core::security::mgmt::ManagementMessageType;
use sec_core::time::Ticks;

#[test]
fn clean_udp_passes() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    let v = e.process(
        &mut udp(PEER_IP, 5000, 80, b"GET / HTTP/1.1"),
        Ticks::new(1),
        &mut sink,
    );

    assert_eq!(v, Verdict::Passed);
    assert_eq!(e.interval_stats().passed, 1);
}

#[test]
fn traffic_to_blocked_port_is_dropped_with_firewall_alert() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    let v = e.process(
        &mut udp(PEER_IP, 5000, DEFAULT_BLOCKED_PORT, b"hello"),
        Ticks::new(1),
        &mut sink,
    );

    assert_eq!(v, Verdict::Dropped(AlertReason::Firewall));
    assert!(sink.alert_reasons().contains(&AlertReason::Firewall));
}

#[test]
fn signature_match_is_dropped_as_malware() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    let v = e.process(
        &mut udp(PEER_IP, 5000, 80, b"x UNION SELECT 1"),
        Ticks::new(1),
        &mut sink,
    );

    assert_eq!(v, Verdict::Dropped(AlertReason::Malware));
}

#[test]
fn xmas_scan_is_dropped_by_heuristics() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    let v = e.process(
        &mut tcp(PEER_IP, 5000, 80, 0x29, b""),
        Ticks::new(1),
        &mut sink,
    );

    assert_eq!(v, Verdict::Dropped(AlertReason::Heuristic));
}

#[test]
fn heavy_hitter_is_banned_after_threshold() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut last = Verdict::Passed;

    for i in 0..200u64 {
        last = e.process(
            &mut udp([10, 0, 0, 9], 5000, 80, b"flood"),
            Ticks::new(i * 1_000_000),
            &mut sink,
        );
    }

    assert_eq!(last, Verdict::Dropped(AlertReason::Ddos));
}

#[test]
fn unsigned_mgmt_packet_raises_auth_failure() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    let v = e.process(
        &mut udp(
            PEER_IP,
            40_000,
            sec_core::config::MANAGEMENT_PORT,
            &[0u8; 24],
        ),
        Ticks::new(1),
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
    let _ = e.process(&mut mgmt(1, &body), Ticks::new(1), &mut sink);

    let v = e.process(
        &mut udp(PEER_IP, 5000, 8080, b"hello"),
        Ticks::new(2),
        &mut sink,
    );

    assert_eq!(v, Verdict::Dropped(AlertReason::Firewall));
}

#[test]
fn alerts_go_to_the_operator_after_it_authenticates() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let _ = e.process(
        &mut mgmt(1, &[ManagementMessageType::BlockPort as u8, 0, 99]),
        Ticks::new(1),
        &mut sink,
    );
    sink.sent.clear();

    let _ = e.process(&mut udp(PEER_IP, 5000, 99, b"x"), Ticks::new(2), &mut sink);

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
        Ticks::new(1),
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
        let _ = e.process(
            &mut udp(attacker, 5000, 80, b"flood"),
            Ticks::new(i * 1_000_000),
            &mut sink,
        );
    }
    let flows_when_banned = e.active_flows();

    for port in 0..50u16 {
        let _ = e.process(
            &mut udp(attacker, 6000 + port, 80, b"x"),
            Ticks::new(200_000_000),
            &mut sink,
        );
    }

    assert_eq!(e.active_flows(), flows_when_banned);
}

#[test]
fn telemetry_is_a_signed_report_carrying_the_epoch_and_memory_use() {
    use sec_core::security::report_auth::Telemetry;
    let mut e = engine();
    let mut sink = CaptureSink::default();

    e.send_telemetry(1234, &mut sink);

    let telemetry = Telemetry::decode(&sink.report_bodies()[0]).expect("a telemetry report");
    assert_eq!(telemetry.epoch, common::EPOCH);
    assert_eq!(telemetry.memory_used, 1234);
}

#[test]
fn a_flood_of_blocked_traffic_raises_a_bounded_number_of_alerts() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    for i in 0..500u16 {
        let src = [10, 3, (i >> 8) as u8, i as u8];
        let _ = e.process(
            &mut udp(src, 5000, DEFAULT_BLOCKED_PORT, b"x"),
            Ticks::new(u64::from(i)),
            &mut sink,
        );
    }

    assert_eq!(
        e.interval_stats().firewall,
        50,
        "the global rate limit admits 50"
    );
    assert!(
        sink.alert_reasons().len() <= 32,
        "{} alerts",
        sink.alert_reasons().len()
    );
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
            last = e.process(
                &mut udp(attacker, 5000, 80, b"burst"),
                Ticks::new(*now),
                &mut sink,
            );
        }
        last
    };

    let first = send_burst(&mut e, &mut now);
    e.end_detection_interval(&mut CaptureSink::default());
    let second = send_burst(&mut e, &mut now);

    assert_eq!(
        first,
        Verdict::Passed,
        "90 packets alone stay under the threshold"
    );
    assert_eq!(second, Verdict::Dropped(AlertReason::Ddos));
}

#[test]
fn a_sudden_surge_of_distinct_sources_is_reported_once() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut now = 0;
    let mut interval = |e: &mut sec_core::engine::Engine, sources: u32, sink: &mut CaptureSink| {
        for s in 0..sources {
            now += 50_000;
            let src = (s | 0x0B00_0000).to_be_bytes();
            let _ = e.process(&mut udp(src, 5000, 80, b"x"), Ticks::new(now), sink);
        }
        e.end_detection_interval(sink);
    };
    for _ in 0..8 {
        interval(&mut e, 200, &mut sink);
    }
    let quiet = sink.alert_reasons().contains(&AlertReason::SourceSurge);

    interval(&mut e, 5_000, &mut sink);
    interval(&mut e, 5_000, &mut sink);

    assert!(!quiet, "steady traffic raised a surge alert");
    let surges = sink
        .alert_reasons()
        .iter()
        .filter(|&&r| r == AlertReason::SourceSurge)
        .count();
    assert_eq!(surges, 1);
}

/// Bytes 20-21 of the frame: the IPv4 flags and fragment offset.
fn with_flags_and_fragment_offset(mut frame: Vec<u8>, field: u16) -> Vec<u8> {
    frame[20..22].copy_from_slice(&field.to_be_bytes());
    frame
}

#[test]
fn ipv4_header_shorter_than_twenty_bytes_is_dropped_as_malformed() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut frame = udp(PEER_IP, 5000, 80, b"hello");
    frame[14] = 0x44;
    frame[16..18].copy_from_slice(&DEFAULT_BLOCKED_PORT.to_be_bytes());

    let v = e.process(&mut frame, Ticks::new(1), &mut sink);

    assert_eq!(v, Verdict::Dropped(AlertReason::MalformedIp));
}

#[test]
fn ipv4_version_other_than_four_is_dropped_as_malformed() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut frame = udp(PEER_IP, 5000, 80, b"hello");
    frame[14] = 0x65;

    let v = e.process(&mut frame, Ticks::new(1), &mut sink);

    assert_eq!(v, Verdict::Dropped(AlertReason::MalformedIp));
}

#[test]
fn non_first_fragment_is_dropped() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut frame = with_flags_and_fragment_offset(udp(PEER_IP, 5000, 80, b"hello"), 100);

    let v = e.process(&mut frame, Ticks::new(1), &mut sink);

    assert_eq!(v, Verdict::Dropped(AlertReason::IpFragment));
}

#[test]
fn first_fragment_is_dropped() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let more_fragments = 0x2000;
    let mut frame =
        with_flags_and_fragment_offset(udp(PEER_IP, 5000, 80, b"hello"), more_fragments);

    let v = e.process(&mut frame, Ticks::new(1), &mut sink);

    assert_eq!(v, Verdict::Dropped(AlertReason::IpFragment));
}

#[test]
fn dont_fragment_flag_alone_does_not_make_a_fragment() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let dont_fragment = 0x4000;
    let mut frame =
        with_flags_and_fragment_offset(udp(PEER_IP, 5000, 80, b"GET / HTTP/1.1"), dont_fragment);

    let v = e.process(&mut frame, Ticks::new(1), &mut sink);

    assert_eq!(v, Verdict::Passed);
}

const PSH_ACK: u8 = 0x18;

#[test]
fn tcp_payload_shorter_than_four_bytes_is_scanned_for_runtime_patterns() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut add_pattern = vec![ManagementMessageType::AddDpiPattern as u8, 3];
    add_pattern.extend_from_slice(b"abc");
    let _ = e.process(&mut mgmt(1, &add_pattern), Ticks::new(1), &mut sink);

    let v = e.process(
        &mut tcp(PEER_IP, 5000, 80, PSH_ACK, b"abc"),
        Ticks::new(2),
        &mut sink,
    );

    assert_eq!(v, Verdict::Dropped(AlertReason::Malware));
}

#[test]
fn tcp_segment_without_payload_is_consumed() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let ack = 0x10;

    let v = e.process(
        &mut tcp(PEER_IP, 5000, 80, ack, b""),
        Ticks::new(1),
        &mut sink,
    );

    assert_eq!(v, Verdict::Consumed);
}

/// Bytes 16-17 of the frame: the IPv4 total length.
fn with_ip_total_length(mut frame: Vec<u8>, total: u16) -> Vec<u8> {
    frame[16..18].copy_from_slice(&total.to_be_bytes());
    frame
}

#[test]
fn tcp_payload_inspection_stops_at_the_ip_total_length() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut frame = tcp(PEER_IP, 5000, 80, PSH_ACK, b"hello");
    frame.extend_from_slice(b"UNION SELECT");

    let v = e.process(&mut frame, Ticks::new(1), &mut sink);

    assert_eq!(v, Verdict::Passed);
}

#[test]
fn udp_payload_inspection_skips_the_udp_header() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let payload = b"al(1)";
    let mut l4 = Vec::new();
    l4.extend_from_slice(&5000u16.to_be_bytes());
    l4.extend_from_slice(&80u16.to_be_bytes());
    l4.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    l4.extend_from_slice(b"ev");
    l4.extend_from_slice(payload);
    let mut frame = ipv4(PEER_IP, 17, &l4);

    let v = e.process(&mut frame, Ticks::new(1), &mut sink);

    assert_eq!(v, Verdict::Passed);
}

#[test]
fn udp_payload_inspection_stops_at_the_udp_length() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut frame = udp(PEER_IP, 5000, 80, b"hello UNION SELECT");
    let udp_length = u16::try_from(8 + b"hello".len()).unwrap();
    frame[38..40].copy_from_slice(&udp_length.to_be_bytes());

    let v = e.process(&mut frame, Ticks::new(1), &mut sink);

    assert_eq!(v, Verdict::Passed);
}

#[test]
fn ipv4_total_length_beyond_the_frame_is_dropped_as_malformed() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let frame = udp(PEER_IP, 5000, 80, b"hello");
    let past_the_end = u16::try_from(frame.len() - 14 + 1).unwrap();
    let mut frame = with_ip_total_length(frame, past_the_end);

    let v = e.process(&mut frame, Ticks::new(1), &mut sink);

    assert_eq!(v, Verdict::Dropped(AlertReason::MalformedIp));
}

#[test]
fn ipv4_total_length_shorter_than_its_header_is_dropped_as_malformed() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut frame = with_ip_total_length(udp(PEER_IP, 5000, 80, b"hello"), 19);

    let v = e.process(&mut frame, Ticks::new(1), &mut sink);

    assert_eq!(v, Verdict::Dropped(AlertReason::MalformedIp));
}

/// Offset of the TCP or UDP header in the frames `common` builds.
const L4: usize = 34;

fn verdict_for(mut frame: Vec<u8>) -> (Verdict, Vec<AlertReason>) {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let v = e.process(&mut frame, Ticks::new(1), &mut sink);
    (v, sink.alert_reasons())
}

#[test]
fn a_tcp_header_cut_short_by_the_ip_total_length_is_dropped_as_malformed() {
    let frame = tcp(PEER_IP, 5000, DEFAULT_BLOCKED_PORT, 0x02, b"");
    let frame = with_ip_total_length(frame, 20 + 10);

    let (v, alerts) = verdict_for(frame);

    assert_eq!(v, Verdict::Dropped(AlertReason::MalformedIp));
    assert_eq!(alerts, [AlertReason::MalformedIp]);
}

#[test]
fn a_tcp_data_offset_under_five_words_is_dropped_as_malformed() {
    let mut frame = tcp(PEER_IP, 5000, 80, PSH_ACK, b"hello");
    frame[L4 + 12] = 0x40;

    assert_eq!(
        verdict_for(frame).0,
        Verdict::Dropped(AlertReason::MalformedIp)
    );
}

#[test]
fn a_tcp_data_offset_past_the_datagram_is_dropped_as_malformed() {
    let mut frame = tcp(PEER_IP, 5000, 80, PSH_ACK, b"hello");
    frame[L4 + 12] = 0xF0;

    assert_eq!(
        verdict_for(frame).0,
        Verdict::Dropped(AlertReason::MalformedIp)
    );
}

#[test]
fn a_udp_length_shorter_than_its_header_is_dropped_as_malformed() {
    let mut frame = udp(PEER_IP, 5000, 80, b"hello");
    frame[L4 + 4..L4 + 6].copy_from_slice(&7u16.to_be_bytes());

    assert_eq!(
        verdict_for(frame).0,
        Verdict::Dropped(AlertReason::MalformedIp)
    );
}

#[test]
fn a_udp_length_past_the_datagram_is_dropped_as_malformed() {
    let mut frame = udp(PEER_IP, 5000, 80, b"hello");
    frame.extend_from_slice(&[0; 8]);
    frame[L4 + 4..L4 + 6].copy_from_slice(&(8u16 + 5 + 1).to_be_bytes());

    assert_eq!(
        verdict_for(frame).0,
        Verdict::Dropped(AlertReason::MalformedIp)
    );
}

#[test]
fn an_icmp_message_shorter_than_its_header_is_dropped_as_malformed() {
    let frame = ipv4(PEER_IP, 1, &[8, 0, 0, 0]);

    assert_eq!(
        verdict_for(frame).0,
        Verdict::Dropped(AlertReason::MalformedIp)
    );
}

#[test]
fn a_new_flow_is_alerted_only_on_sampled_ticks() {
    use sec_core::config::FLOW_LOG_SAMPLE_MASK;
    let sampled = Ticks::new(FLOW_LOG_SAMPLE_MASK + 1);
    let unsampled = Ticks::new(FLOW_LOG_SAMPLE_MASK + 2);
    let mut e = engine();
    let mut sink = CaptureSink::default();

    let _ = e.process(&mut udp(PEER_IP, 5000, 80, b"a"), sampled, &mut sink);
    let _ = e.process(&mut udp(PEER_IP, 5001, 80, b"b"), unsampled, &mut sink);

    let flows = sink
        .alert_reasons()
        .iter()
        .filter(|&&r| r == AlertReason::Flow)
        .count();
    assert_eq!(flows, 1);
}

#[test]
fn a_nop_sled_payload_is_dropped_as_a_heuristic_with_an_alert() {
    let (v, alerts) = verdict_for(udp(PEER_IP, 5000, 80, &[0x90; 64]));

    assert_eq!(v, Verdict::Dropped(AlertReason::Heuristic));
    assert!(alerts.contains(&AlertReason::Heuristic));
}
