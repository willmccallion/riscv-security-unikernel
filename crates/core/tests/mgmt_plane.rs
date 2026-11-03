//! The operator must always be able to reach the mgmt plane, and mgmt
//! handling must not open holes in the data plane.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{CaptureSink, PEER_IP, PEER_MAC, acks, engine, mgmt, tcp, udp};
use sec_core::config::MANAGEMENT_PORT;
use sec_core::engine::{Engine, Verdict};
use sec_core::net::stack::checksum;
use sec_core::security::alert::AlertReason;
use sec_core::security::mgmt::{ManagementMessageType, MgmtOutcome};
use sec_core::security::vm::Opcode;

const PROBE_PORT: u16 = 7777;

fn block_port(port: u16) -> Vec<u8> {
    let mut body = vec![ManagementMessageType::BlockPort as u8];
    body.extend_from_slice(&port.to_be_bytes());
    body
}

fn single_instruction_upload(op: Opcode, imm: u32) -> Vec<u8> {
    let mut body = vec![
        ManagementMessageType::UploadBpfProgram as u8,
        1,
        op as u8,
        0,
        0,
    ];
    body.extend_from_slice(&imm.to_be_bytes());
    body
}

fn pass_all_program() -> Vec<u8> {
    single_instruction_upload(Opcode::Ret, 1)
}

/// True if fresh commands from the operator take effect: replace any BPF
/// program with pass-all, block `PROBE_PORT`, then check a probe sent
/// once the data-plane rate limit has refilled hits the firewall.
fn operator_can_still_manage(e: &mut Engine, first_seq: u32, now: u64) -> bool {
    let mut sink = CaptureSink::default();
    let _ = e.process(&mut mgmt(first_seq, &pass_all_program()), now, &mut sink);
    let _ = e.process(
        &mut mgmt(first_seq + 1, &block_port(PROBE_PORT)),
        now,
        &mut sink,
    );
    let later = now + 1_000_000_000;
    let probe = e.process(
        &mut udp([10, 9, 9, 9], 5000, PROBE_PORT, b"probe"),
        later,
        &mut sink,
    );
    probe == Verdict::Dropped(AlertReason::Firewall)
}

#[test]
fn drop_all_bpf_program_does_not_lock_out_the_operator() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let drop_all = single_instruction_upload(Opcode::Ret, 0);
    let _ = e.process(&mut mgmt(1, &drop_all), 1, &mut sink);

    assert!(operator_can_still_manage(&mut e, 2, 2));
}

#[test]
fn bpf_upload_that_can_run_past_its_end_is_rejected_and_keeps_the_active_program() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let drop_all = single_instruction_upload(Opcode::Ret, 0);
    let no_return = single_instruction_upload(Opcode::Nop, 0);
    let _ = e.process(&mut mgmt(1, &drop_all), 1, &mut sink);

    let _ = e.process(&mut mgmt(2, &no_return), 2, &mut sink);
    let later = 2 + 1_000_000_000;
    let verdict = e.process(
        &mut udp([10, 9, 9, 9], 5000, 80, b"probe"),
        later,
        &mut sink,
    );

    let outcome = acks(&sink).last().map(|&(_, _, outcome)| outcome);
    assert_eq!(outcome, Some(MgmtOutcome::Invalid as u8));
    assert_eq!(verdict, Verdict::Dropped(AlertReason::Bpf));
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

    let v = e.process(
        &mut udp([10, 9, 9, 9], 5000, 0x9090, b"probe"),
        2,
        &mut sink,
    );

    assert_eq!(v, Verdict::Dropped(AlertReason::Firewall));
}

#[test]
fn ethernet_padding_after_a_mgmt_datagram_does_not_break_its_mac() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut frame = mgmt(1, &block_port(PROBE_PORT));
    frame.extend_from_slice(&[0; 6]);
    let _ = e.process(&mut frame, 1, &mut sink);

    let v = e.process(
        &mut udp([10, 9, 9, 9], 5000, PROBE_PORT, b"probe"),
        2,
        &mut sink,
    );

    assert_eq!(v, Verdict::Dropped(AlertReason::Firewall));
}

#[test]
fn tcp_to_the_mgmt_port_is_still_inspected() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    let v = e.process(
        &mut tcp([10, 9, 9, 9], 5000, MANAGEMENT_PORT, 0x18, b"UNION SELECT"),
        1,
        &mut sink,
    );

    assert_eq!(v, Verdict::Dropped(AlertReason::Malware));
}

#[test]
fn unauthenticated_mgmt_flood_is_rate_limited() {
    let mut e = engine();
    let mut sink = CaptureSink::default();

    for i in 0..500u16 {
        let _ = e.process(
            &mut udp([10, 2, 0, 1], 1000 + i, MANAGEMENT_PORT, &[0xEE; 24]),
            1,
            &mut sink,
        );
    }

    let auth_failures = sink
        .alert_reasons()
        .iter()
        .filter(|&&r| r == AlertReason::MgmtAuthFail)
        .count();
    assert!(
        auth_failures <= 32,
        "{auth_failures} auth-failure alerts for one instant"
    );
}

#[test]
fn operator_regains_access_once_a_mgmt_flood_stops() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    for i in 0..500u16 {
        let _ = e.process(
            &mut udp([10, 2, 0, 1], 1000 + i, MANAGEMENT_PORT, &[0xEE; 24]),
            1,
            &mut sink,
        );
    }

    assert!(operator_can_still_manage(&mut e, 1, 1_000_000_000));
}

#[test]
fn operator_commands_take_effect_during_a_mgmt_flood() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    for i in 0..500u16 {
        let _ = e.process(
            &mut udp([10, 2, 0, 1], 1000 + i, MANAGEMENT_PORT, &[0xEE; 24]),
            1,
            &mut sink,
        );
    }

    assert!(operator_can_still_manage(&mut e, 1, 1));
}

fn ban_ip(ip: [u8; 4]) -> Vec<u8> {
    command(ManagementMessageType::BanIp, &ip)
}

/// Floods from `src` until the heavy-hitter sketch bans it.
fn flood_until_banned(e: &mut Engine, src: [u8; 4], now: u64, sink: &mut CaptureSink) {
    for i in 0..=sec_core::config::HEAVY_HITTER_THRESHOLD {
        let _ = e.process(&mut udp(src, 6000 + i, 80, b"flood"), now, sink);
    }
}

#[test]
fn automatic_bans_do_not_evict_an_operator_ban() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let target = [10, 9, 9, 9];
    let _ = e.process(&mut mgmt(1, &ban_ip(target)), 1, &mut sink);
    for i in 0..16u8 {
        flood_until_banned(&mut e, [20 + i, 1, 1, 1], 2, &mut sink);
    }

    let later = 1_000_000_000;
    let v = e.process(&mut udp(target, 5000, 80, b"hello"), later, &mut sink);

    assert_eq!(v, Verdict::Dropped(AlertReason::Ddos));
}

#[test]
fn operator_ban_beyond_a_table_full_of_operator_bans_is_acked_as_table_full() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    for i in 0..16u8 {
        let _ = e.process(
            &mut mgmt(u32::from(i) + 1, &ban_ip([10, 0, 0, i])),
            1,
            &mut sink,
        );
    }

    let _ = e.process(&mut mgmt(17, &ban_ip([10, 0, 1, 1])), 1, &mut sink);

    let outcome = acks(&sink).last().map(|&(_, _, outcome)| outcome);
    assert_eq!(outcome, Some(MgmtOutcome::TableFull as u8));
}

/// A dashboard that restarts within one kernel boot learns from telemetry
/// where to resume its sequence.
#[test]
fn telemetry_reports_the_last_accepted_mgmt_sequence() {
    use sec_core::security::report_auth::telemetry_packet::{LAST_MGMT_SEQ_SLOT, SLOTS_OFFSET};
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let _ = e.process(&mut mgmt(41, &block_port(8080)), 1, &mut sink);

    e.send_telemetry(0, &mut sink);

    let telemetry = sink.report_bodies().pop().expect("telemetry was sent");
    let at = SLOTS_OFFSET + LAST_MGMT_SEQ_SLOT * 8;
    let last_seq = u64::from_be_bytes(telemetry[at..at + 8].try_into().unwrap());
    assert_eq!(last_seq, 41);
}

#[test]
fn every_authenticated_command_is_acknowledged_with_its_outcome() {
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
        let _ = e.process(
            &mut mgmt(u32::from(i) + 1, &block_port(9000 + i)),
            1,
            &mut sink,
        );
    }
    sink.sent.clear();

    let _ = e.process(&mut mgmt(100, &block_port(9999)), 2, &mut sink);

    let outcome = common::acks(&sink).last().map(|&(_, _, o)| o);
    assert_eq!(outcome, Some(MgmtOutcome::TableFull as u8));
}

fn command(kind: ManagementMessageType, operand: &[u8]) -> Vec<u8> {
    let mut body = vec![kind as u8];
    body.extend_from_slice(operand);
    body
}

#[test]
fn unblock_port_reopens_a_blocked_port() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let _ = e.process(&mut mgmt(1, &block_port(PROBE_PORT)), 1, &mut sink);
    let unblock = command(
        ManagementMessageType::UnblockPort,
        &PROBE_PORT.to_be_bytes(),
    );
    let _ = e.process(&mut mgmt(2, &unblock), 2, &mut sink);

    let v = e.process(
        &mut udp([10, 9, 9, 9], 5000, PROBE_PORT, b"probe"),
        3,
        &mut sink,
    );

    assert_eq!(v, Verdict::Passed);
}

#[test]
fn remove_dpi_pattern_stops_matching_it() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let operand = [&[6u8][..], b"needle"].concat();
    let _ = e.process(
        &mut mgmt(1, &command(ManagementMessageType::AddDpiPattern, &operand)),
        1,
        &mut sink,
    );
    let _ = e.process(
        &mut mgmt(
            2,
            &command(ManagementMessageType::RemoveDpiPattern, &operand),
        ),
        2,
        &mut sink,
    );

    let v = e.process(
        &mut udp([10, 9, 9, 9], 5000, 80, b"a needle here"),
        3,
        &mut sink,
    );

    assert_eq!(v, Verdict::Passed);
}

#[test]
fn unload_bpf_program_stops_filtering() {
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
    let _ = e.process(
        &mut mgmt(2, &command(ManagementMessageType::UnloadBpfProgram, &[])),
        2,
        &mut sink,
    );

    let v = e.process(&mut udp([10, 9, 9, 9], 5000, 80, b"hello"), 3, &mut sink);

    assert_eq!(v, Verdict::Passed);
}

#[test]
fn unban_ip_lets_the_source_back_in() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let target = [10, 9, 9, 9];
    let _ = e.process(
        &mut mgmt(1, &command(ManagementMessageType::BanIp, &target)),
        1,
        &mut sink,
    );
    let _ = e.process(
        &mut mgmt(2, &command(ManagementMessageType::UnbanIp, &target)),
        2,
        &mut sink,
    );

    let v = e.process(&mut udp(target, 5000, 80, b"hello"), 3, &mut sink);

    assert_eq!(v, Verdict::Passed);
}

/// A copy of `frame` that appears to come from another host on the mgmt LAN.
fn resent_from_another_host(frame: &[u8]) -> Vec<u8> {
    let mut resent = frame.to_vec();
    resent[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, 0x66]);
    resent[26..30].copy_from_slice(&[192, 168, 100, 66]);
    resent[24..26].copy_from_slice(&[0, 0]);
    let csum = checksum(&resent[14..34]);
    resent[24..26].copy_from_slice(&csum.to_be_bytes());
    resent
}

#[test]
fn a_captured_command_resent_from_another_host_does_not_redirect_reports() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut resent = resent_from_another_host(&mgmt(1, &block_port(9000)));

    let _ = e.process(&mut resent, 1, &mut sink);

    let destinations: Vec<_> = sink
        .sent
        .iter()
        .map(|f| {
            (
                <[u8; 6]>::try_from(&f[0..6]).unwrap(),
                <[u8; 4]>::try_from(&f[30..34]).unwrap(),
            )
        })
        .collect();
    assert!(!destinations.is_empty(), "the command was not acked");
    assert!(
        destinations.iter().all(|&dest| dest == (PEER_MAC, PEER_IP)),
        "reports went to {destinations:?}"
    );
}
