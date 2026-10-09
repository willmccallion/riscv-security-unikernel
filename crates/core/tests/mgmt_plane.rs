//! The operator must always be able to reach the mgmt plane, and mgmt
//! handling must not open holes in the data plane.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{CaptureSink, PEER_IP, engine, mgmt, tcp, udp};
use sec_core::config::MANAGEMENT_PORT;
use sec_core::engine::{Engine, Verdict};
use sec_core::security::alert::AlertReason;
use sec_core::security::mgmt::ManagementMessageType;
use sec_core::security::vm::Opcode;

const PROBE_PORT: u16 = 7777;

fn block_port(port: u16) -> Vec<u8> {
    let mut body = vec![ManagementMessageType::BlockPort as u8];
    body.extend_from_slice(&port.to_be_bytes());
    body
}

fn pass_all_program() -> Vec<u8> {
    vec![ManagementMessageType::UploadBpfProgram as u8, 1, Opcode::Ret as u8, 0, 0, 0, 0, 0, 1]
}

/// True if fresh commands from the operator take effect: replace any BPF
/// program with pass-all, block `PROBE_PORT`, then check a probe sent
/// once the data-plane rate limit has refilled hits the firewall.
fn operator_can_still_manage(e: &mut Engine, first_seq: u32, now: u64) -> bool {
    let mut sink = CaptureSink::default();
    let _ = e.process(&mut mgmt(first_seq, &pass_all_program()), now, &mut sink);
    let _ = e.process(&mut mgmt(first_seq + 1, &block_port(PROBE_PORT)), now, &mut sink);
    let later = now + 1_000_000_000;
    let probe = e.process(&mut udp([10, 9, 9, 9], 5000, PROBE_PORT, b"probe"), later, &mut sink);
    probe == Verdict::Dropped(AlertReason::Firewall)
}

#[test]
fn drop_all_bpf_program_does_not_lock_out_the_operator() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let drop_all = [
        ManagementMessageType::UploadBpfProgram as u8,
        1,
        Opcode::Ret as u8,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let _ = e.process(&mut mgmt(1, &drop_all), 1, &mut sink);

    assert!(operator_can_still_manage(&mut e, 2, 2));
}

#[test]
fn banning_the_operator_ip_does_not_lock_out_the_operator() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut ban_self = vec![ManagementMessageType::BanIp as u8];
    ban_self.extend_from_slice(&PEER_IP);
    let _ = e.process(&mut mgmt(1, &ban_self), 1, &mut sink);

    assert!(operator_can_still_manage(&mut e, 2, 2));
}

#[test]
fn exhausting_the_data_plane_rate_limit_does_not_lock_out_the_operator() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    for i in 0..200u8 {
        let _ = e.process(&mut udp([10, 1, 0, i], 5000, 80, b"flood"), 1, &mut sink);
    }

    assert!(operator_can_still_manage(&mut e, 1, 1));
}

#[test]
fn mgmt_body_resembling_a_nop_sled_is_dispatched() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut body = block_port(0x9090);
    body.extend_from_slice(&[0x90; 16]);
    let _ = e.process(&mut mgmt(1, &body), 1, &mut sink);

    let v = e.process(&mut udp([10, 9, 9, 9], 5000, 0x9090, b"probe"), 2, &mut sink);

    assert_eq!(v, Verdict::Dropped(AlertReason::Firewall));
}

#[test]
fn ethernet_padding_after_a_mgmt_datagram_does_not_break_its_mac() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut frame = mgmt(1, &block_port(PROBE_PORT));
    frame.extend_from_slice(&[0; 6]);
    let _ = e.process(&mut frame, 1, &mut sink);

    let v = e.process(&mut udp([10, 9, 9, 9], 5000, PROBE_PORT, b"probe"), 2, &mut sink);

    assert_eq!(v, Verdict::Dropped(AlertReason::Firewall));
}

#[test]
fn tcp_to_the_mgmt_port_is_still_inspected() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    let v = e.process(&mut tcp([10, 9, 9, 9], 5000, MANAGEMENT_PORT, 0x18, b"UNION SELECT"), 1, &mut sink);

    assert_eq!(v, Verdict::Dropped(AlertReason::Malware));
}

#[test]
fn unauthenticated_mgmt_flood_is_rate_limited() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    for i in 0..500u16 {
        let _ = e.process(&mut udp([10, 2, 0, 1], 1000 + i, MANAGEMENT_PORT, &[0xEE; 24]), 1, &mut sink);
    }

    let auth_failures = sink
        .alert_reasons()
        .iter()
        .filter(|&&r| r == AlertReason::MgmtAuthFail.as_u8())
        .count();
    assert!(auth_failures <= 32, "{auth_failures} auth-failure alerts for one instant");
}

#[test]
fn operator_regains_access_once_a_mgmt_flood_stops() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    for i in 0..500u16 {
        let _ = e.process(&mut udp([10, 2, 0, 1], 1000 + i, MANAGEMENT_PORT, &[0xEE; 24]), 1, &mut sink);
    }

    assert!(operator_can_still_manage(&mut e, 1, 1_000_000_000));
}

#[test]
fn every_authenticated_command_is_acknowledged_with_its_outcome() {
    use sec_core::security::mgmt::MgmtOutcome;
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let block = ManagementMessageType::BlockPort as u8;

    let _ = e.process(&mut mgmt(1, &block_port(8080)), 1, &mut sink);
    let _ = e.process(&mut mgmt(2, &block_port(MANAGEMENT_PORT)), 2, &mut sink);
    let _ = e.process(&mut mgmt(3, &[block]), 3, &mut sink);
    let _ = e.process(&mut mgmt(4, &[0xEE]), 4, &mut sink);

    assert_eq!(
        common::acks(&sink),
        [
            (1, block, MgmtOutcome::Applied as u8),
            (2, block, MgmtOutcome::Refused as u8),
            (3, block, MgmtOutcome::Invalid as u8),
            (4, 0xEE, MgmtOutcome::Invalid as u8),
        ]
    );
}

#[test]
fn full_firewall_table_is_reported_in_the_ack() {
    use sec_core::security::mgmt::MgmtOutcome;
    let mut e = engine();
    let mut sink = CaptureSink::default();
    for i in 0..15u16 {
        let _ = e.process(&mut mgmt(u32::from(i) + 1, &block_port(9000 + i)), 1, &mut sink);
    }
    sink.sent.clear();

    let _ = e.process(&mut mgmt(100, &block_port(9999)), 2, &mut sink);

    let outcome = common::acks(&sink).last().map(|&(_, _, o)| o);
    assert_eq!(outcome, Some(MgmtOutcome::TableFull as u8));
}
