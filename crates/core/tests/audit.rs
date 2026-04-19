//! Regression tests for the security primitives that the unikernel
//! and the Linux daemon both depend on.
//!
//! Each test exercises a single observable invariant of `sec_core`:
//! the SYN-cookie reply path, TCP DPI hand-off, the eBPF VM's
//! out-of-range tolerance, the penalty-box eviction policy, the ARP
//! parser, the heuristic engine, the flow table, and the Aho-Corasick
//! trie. They are written so they fail loudly when the invariant is
//! violated.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::missing_panics_doc
)]

use sec_core::net::PacketSink;
use sec_core::net::constants::{SYN_COOKIE_MAGIC, arp, ethernet, ipv4, tcp};
use sec_core::net::stack::{SynCookieSecret, checksum, process_packet};
use sec_core::net::tcp::{TCP_ACK, TCP_SYN, TcpHeader};
use sec_core::security::dos::PenaltyBox;
use sec_core::security::dpi::AhoCorasick;
use sec_core::security::flow::FlowTable;
use sec_core::security::heuristic::HeuristicEngine;
use sec_core::security::mgmt_auth::{MgmtAuth, seal};
use sec_core::security::vm::{Instruction, VM};

/// Captures every frame the stack hands to its sink so tests can
/// inspect what was actually sent.
#[derive(Default)]
struct CaptureSink {
    sent: Vec<Vec<u8>>,
}

impl PacketSink for CaptureSink {
    fn send(&mut self, frame: &[u8]) {
        self.sent.push(frame.to_vec());
    }
}

/// Kernel IP from `sec_core::config::IP_ADDR` (192.168.100.2).
const KERNEL_IP: [u8; 4] = [192, 168, 100, 2];
/// Kernel MAC from `sec_core::config::MAC_ADDR`.
const KERNEL_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

/// Deterministic SYN-cookie secret used by every test that exercises
/// the SYN-ACK reply path. Real kernels build one per boot from
/// `mcycle` XOR MAC; tests need a fixed value so cookies are
/// reproducible.
fn test_syn_secret() -> SynCookieSecret {
    SynCookieSecret::new([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ])
}

/// Build a minimal Ethernet+IPv4+TCP frame of the requested kind.
fn build_tcp_frame(
    src_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    flags: u16,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    let total = ethernet::MIN_FRAME_SIZE
        + ipv4::MIN_HEADER_SIZE
        + tcp::MIN_HEADER_SIZE
        + payload.len();
    let mut f = vec![0u8; total];

    f[0..6].copy_from_slice(&KERNEL_MAC);
    f[6..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    f[ethernet::TYPE_OFFSET] = 0x08;
    f[ethernet::TYPE_OFFSET + 1] = 0x00;

    f[ipv4::VERSION_IHL_OFFSET] = 0x45;
    f[ipv4::PROTOCOL_OFFSET] = 6;
    f[ipv4::SRC_IP_OFFSET..ipv4::SRC_IP_OFFSET + 4].copy_from_slice(&src_ip);
    f[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + 4].copy_from_slice(&KERNEL_IP);

    let tcp_off = ethernet::MIN_FRAME_SIZE + ipv4::MIN_HEADER_SIZE;
    f[tcp_off] = (src_port >> 8) as u8;
    f[tcp_off + 1] = src_port as u8;
    f[tcp_off + 2] = (dst_port >> 8) as u8;
    f[tcp_off + 3] = dst_port as u8;
    f[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
    let dof = (5u16 << 12) | flags;
    f[tcp_off + 12] = (dof >> 8) as u8;
    f[tcp_off + 13] = dof as u8;

    let payload_off = tcp_off + tcp::MIN_HEADER_SIZE;
    f[payload_off..payload_off + payload.len()].copy_from_slice(payload);

    f
}

/// Build a minimal Ethernet+ARP request frame with a configurable
/// hardware-type field at bytes 14..16.
fn build_arp_request(hw_type_be: [u8; 2], target_ip: [u8; 4]) -> Vec<u8> {
    let mut f = vec![0u8; arp::MIN_PACKET_SIZE];
    f[0..6].copy_from_slice(&[0xFF; 6]);
    f[6..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    f[ethernet::TYPE_OFFSET] = 0x08;
    f[ethernet::TYPE_OFFSET + 1] = 0x06;
    f[14] = hw_type_be[0];
    f[15] = hw_type_be[1];
    f[16] = 0x08;
    f[17] = 0x00;
    f[18] = 0x06;
    f[19] = 0x04;
    f[20] = 0x00;
    f[21] = 0x01;
    f[22..28].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    f[28..32].copy_from_slice(&[10, 0, 0, 1]);
    f[32..38].copy_from_slice(&[0; 6]);
    f[38..42].copy_from_slice(&target_ip);
    f
}

/// The deleted spoof-magic backdoor used to rewrite `src_ip` from
/// constants in `config.rs`. None of those constants must come back.
#[test]
fn config_does_not_reintroduce_spoof_magic_constants() {
    let src = include_str!("../src/config.rs");
    assert!(
        !src.contains("SPOOF_DETECTION_MAGIC"),
        "config.rs still contains SPOOF_DETECTION_MAGIC"
    );
    assert!(
        !src.contains("SPOOF_DETECTION_IP_OFFSET"),
        "config.rs still contains SPOOF_DETECTION_IP_OFFSET"
    );
    assert!(
        !src.contains("SPOOF_DETECTION_MIN_LEN"),
        "config.rs still contains SPOOF_DETECTION_MIN_LEN"
    );
}

/// Two SYN segments that share `(src_ip, src_port)` but target
/// different destination ports must produce different SYN-ACK
/// sequence numbers. A trivial cookie that ignores the destination
/// port lets an attacker compute valid replies for any port given a
/// single observation.
#[test]
fn syn_cookie_depends_on_destination_port() {
    let mut sink_a = CaptureSink::default();
    let mut sink_b = CaptureSink::default();

    let mut frame_a = build_tcp_frame([10, 0, 0, 7], 4444, 80, TCP_SYN, 0xDEAD_BEEF, &[]);
    let mut frame_b = build_tcp_frame([10, 0, 0, 7], 4444, 443, TCP_SYN, 0xDEAD_BEEF, &[]);

    let secret = test_syn_secret();
    let _ = process_packet(&mut frame_a, &mut sink_a, &secret);
    let _ = process_packet(&mut frame_b, &mut sink_b, &secret);

    assert_eq!(sink_a.sent.len(), 1, "SYN to dst=80 should be answered");
    assert_eq!(sink_b.sent.len(), 1, "SYN to dst=443 should be answered");

    let seq_a = read_seq(&sink_a.sent[0]);
    let seq_b = read_seq(&sink_b.sent[0]);
    assert_ne!(
        seq_a, seq_b,
        "SYN-ACK sequence numbers must differ for distinct destination ports"
    );
}

/// The SYN-cookie sequence number must not equal a value an off-path
/// attacker can derive from public packet headers and a compile-time
/// constant; it has to incorporate a per-boot secret.
#[test]
fn syn_cookie_is_not_derivable_from_public_inputs() {
    let mut sink = CaptureSink::default();
    let src = [10, 0, 0, 9];
    let src_port: u16 = 51_234;
    let mut frame = build_tcp_frame(src, src_port, 80, TCP_SYN, 0, &[]);

    let secret = test_syn_secret();
    let _ = process_packet(&mut frame, &mut sink, &secret);
    assert_eq!(sink.sent.len(), 1);
    let seq = read_seq(&sink.sent[0]);

    let trivial = (src[3] as u32)
        .wrapping_add(src_port as u32)
        .wrapping_add(SYN_COOKIE_MAGIC);
    assert_ne!(
        seq, trivial,
        "cookie equals src_ip[3] + src_port + magic; needs a per-boot secret"
    );
}

fn read_seq(frame: &[u8]) -> u32 {
    let tcp_off = ethernet::MIN_FRAME_SIZE + ipv4::MIN_HEADER_SIZE;
    u32::from_be_bytes([
        frame[tcp_off + 4],
        frame[tcp_off + 5],
        frame[tcp_off + 6],
        frame[tcp_off + 7],
    ])
}

fn read_flags(frame: &[u8]) -> u16 {
    let tcp_off = ethernet::MIN_FRAME_SIZE + ipv4::MIN_HEADER_SIZE;
    let dof = ((frame[tcp_off + 12] as u16) << 8) | frame[tcp_off + 13] as u16;
    dof & 0x003F
}

/// `process_packet` must hand TCP application bytes back to the
/// caller for inspection on every non-SYN segment; otherwise the DPI
/// engine never sees TCP traffic.
#[test]
fn non_syn_tcp_returns_payload_to_caller() {
    let mut sink = CaptureSink::default();
    let payload = b"GET / HTTP/1.1\r\nDROP TABLE users--";
    let mut frame = build_tcp_frame([10, 0, 0, 5], 1024, 80, TCP_ACK, 1, payload);

    let secret = test_syn_secret();
    let result = process_packet(&mut frame, &mut sink, &secret);
    assert!(
        sink.sent.is_empty(),
        "non-SYN TCP must not generate a SYN-ACK"
    );
    let returned = result.expect("non-SYN TCP must hand the payload back to the caller");
    assert!(
        returned.windows(payload.len()).any(|w| w == payload),
        "returned slice must contain the TCP payload bytes"
    );
}

/// `TcpHeader::extract_ports` is the helper the kernel uses to read
/// the destination port before invoking `process_packet`, so it must
/// produce the right values for raw TCP segments.
#[test]
fn extract_ports_reads_dst_port_from_raw_tcp_segment() {
    let frame = build_tcp_frame([10, 0, 0, 5], 4444, 23, TCP_SYN, 0, &[]);
    let l4_offset = ethernet::MIN_FRAME_SIZE + ipv4::MIN_HEADER_SIZE;
    let (sp, dp) =
        TcpHeader::extract_ports(&frame[l4_offset..]).expect("ports must extract from frame");
    assert_eq!(sp, 4444);
    assert_eq!(dp, 23);
}

/// Regression: a SYN with `seq == u32::MAX` must wrap the ACK number
/// rather than panic on `seq + 1`. Found by the cargo-fuzz
/// `process_packet` target during Checkpoint E.
#[test]
fn process_packet_handles_syn_with_max_seq_without_panicking() {
    let mut sink = CaptureSink::default();
    let mut frame = build_tcp_frame([10, 0, 0, 5], 4444, 80, TCP_SYN, u32::MAX, &[]);
    let secret = test_syn_secret();
    let _ = process_packet(&mut frame, &mut sink, &secret);
}

/// Regression: an ICMP echo request with only one byte of payload
/// past the IP header must not OOB-panic when writing the echo reply
/// header. Found by the cargo-fuzz `process_packet` target.
#[test]
fn process_packet_handles_truncated_icmp_without_panicking() {
    use sec_core::net::constants::{IpProtocol, ethernet, ipv4};
    let total = ethernet::MIN_FRAME_SIZE + ipv4::MIN_HEADER_SIZE + 1;
    let mut frame = vec![0u8; total];
    frame[ethernet::TYPE_OFFSET] = 0x08;
    frame[ethernet::TYPE_OFFSET + 1] = 0x00;
    frame[ipv4::VERSION_IHL_OFFSET] = 0x45;
    frame[ipv4::PROTOCOL_OFFSET] = IpProtocol::Icmp as u8;
    frame[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE]
        .copy_from_slice(&[192, 168, 100, 2]);
    frame[ethernet::MIN_FRAME_SIZE + ipv4::MIN_HEADER_SIZE] = 8; // EchoRequest
    let mut sink = CaptureSink::default();
    let secret = test_syn_secret();
    let _ = process_packet(&mut frame, &mut sink, &secret);
}

/// `process_packet` answers a SYN with a SYN-ACK without consulting
/// any firewall — the firewall gate must therefore live in the caller.
#[test]
fn process_packet_emits_syn_ack_for_syn() {
    let mut sink = CaptureSink::default();
    let mut frame = build_tcp_frame([10, 0, 0, 5], 4444, 80, TCP_SYN, 0, &[]);
    let secret = test_syn_secret();
    let _ = process_packet(&mut frame, &mut sink, &secret);
    assert_eq!(sink.sent.len(), 1, "SYN must produce SYN-ACK");
    let flags = read_flags(&sink.sent[0]);
    assert_eq!(flags & (TCP_SYN | TCP_ACK), TCP_SYN | TCP_ACK);
}

/// The eBPF VM has 16 registers but encodes register indices as `u8`,
/// so an attacker-supplied program can request register 20. The VM
/// must reject or clamp instead of panicking, since a panic in the
/// kernel halts the core.
#[test]
fn vm_rejects_out_of_range_register_index() {
    let prog = [Instruction::new(0x04, 20, 0, 0xFF)];
    let mut vm = VM::new();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        vm.execute(&prog, &[0u8; 64]);
    }));

    assert!(
        result.is_ok(),
        "VM panicked on instruction with reg_a >= 16"
    );
}

/// A jump instruction with a target far beyond the end of the program
/// must terminate cleanly rather than running off into uninitialised
/// memory or panicking.
#[test]
fn vm_rejects_out_of_range_jump_target() {
    let prog = [Instruction::new(0x0A, 0, 0, u32::MAX)];
    let mut vm = VM::new();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        vm.execute(&prog, &[0u8; 64]);
    }));

    assert!(
        result.is_ok(),
        "VM panicked on a jump with an out-of-range target"
    );
}

/// Once the penalty box is full, every additional `ban` call must not
/// land in the same slot deterministically — otherwise an attacker can
/// predict which IPs survive eviction and force the same one to keep
/// flipping out.
#[test]
fn penalty_box_does_not_clobber_a_single_slot_when_full() {
    let mut pbox = PenaltyBox::new();
    let now = 1_000u64;
    let dur = 100_000u64;

    for i in 0..16u8 {
        let ip = [10, 0, 0, i];
        pbox.ban(&ip, dur, now);
        assert!(pbox.is_banned(&ip, now));
    }

    let first = [10, 0, 0, 0];
    assert!(pbox.is_banned(&first, now));

    for i in 16..20u8 {
        let ip = [10, 0, 0, i];
        pbox.ban(&ip, dur, now);
    }

    let surviving = (16..20u8)
        .filter(|i| pbox.is_banned(&[10, 0, 0, *i], now))
        .count();

    assert!(
        surviving >= 2,
        "after 4 overflow bans only {surviving}/4 are still banned; one slot is always overwritten"
    );
}

/// The ARP hardware-type field sits 14 bytes into a standard
/// Ethernet+ARP frame (immediately after the Ethernet header). Any
/// other offset means the parser is reading a different field
/// entirely.
#[test]
fn arp_hw_type_offset_matches_wire_layout() {
    assert_eq!(
        arp::HW_TYPE_OFFSET, 14,
        "ARP hw_type lives at offset 14 of the Ethernet frame, not {}",
        arp::HW_TYPE_OFFSET
    );
}

/// An ARP request whose hardware-type field is not Ethernet (1) must
/// not produce a reply.
#[test]
fn arp_request_with_non_ethernet_hw_type_is_ignored() {
    let mut sink = CaptureSink::default();
    let mut frame = build_arp_request([0xFF, 0xFF], KERNEL_IP);
    let secret = test_syn_secret();
    let _ = process_packet(&mut frame, &mut sink, &secret);
    assert!(
        sink.sent.is_empty(),
        "ARP with hw_type=0xFFFF should not generate a reply"
    );
}

/// The shellcode heuristic must catch sleds in the architecture the
/// kernel is actually executing on. Eight consecutive RISC-V `addi
/// x0, x0, 0` instructions form a textbook sled.
#[test]
fn shellcode_heuristic_detects_riscv_nop_sled() {
    let mut payload = Vec::new();
    for _ in 0..8 {
        payload.extend_from_slice(&0x0000_0013u32.to_le_bytes());
    }
    assert!(
        HeuristicEngine::check_payload(&payload).is_some(),
        "RISC-V NOP sled should trigger the shellcode heuristic"
    );
}

/// Interleaving a non-NOP byte between every pair of NOPs must not be
/// enough to evade the heuristic; otherwise any attacker can defeat
/// it by inserting a single junk byte.
#[test]
fn shellcode_heuristic_resists_interleaved_nop_bypass() {
    let payload: Vec<u8> = (0..200).flat_map(|_| [0x00u8, 0x90, 0x90]).collect();
    assert!(
        HeuristicEngine::check_payload(&payload).is_some(),
        "interleaved NOP pattern should still be flagged"
    );
}

/// The flow table tracks at most a fixed number of 5-tuples. Pure LRU
/// eviction lets a flood of unique 5-tuples purge an existing flow,
/// so the eviction policy must keep recently-seen real flows around.
#[test]
fn flow_table_protects_existing_flow_from_unique_tuple_flood() {
    let mut ft = FlowTable::new();
    let now = 1_000u64;

    let real_seen = ft.update(&[10, 0, 0, 1], &KERNEL_IP, 1234, 80, 6, 100, now);
    assert!(real_seen, "real flow should be created on first sighting");

    for i in 0..100u16 {
        let _ = ft.update(
            &[10, 0, 0, 99],
            &KERNEL_IP,
            10_000 + i,
            12_345,
            6,
            100,
            now + i as u64 + 1,
        );
    }

    let still_known = !ft.update(
        &[10, 0, 0, 1],
        &KERNEL_IP,
        1234,
        80,
        6,
        100,
        now + 200,
    );
    assert!(
        still_known,
        "the original flow was evicted by a unique-5-tuple flood"
    );
}

/// `AhoCorasick::insert` accepts patterns until the trie is full and
/// then silently drops them. Operators have no way to learn that a
/// rule did not actually take effect; the API needs to surface that.
#[test]
fn ahocorasick_signals_when_a_pattern_failed_to_insert() {
    let mut ac = AhoCorasick::new();
    for prefix in 0u8..6 {
        let mut p = Vec::with_capacity(32);
        for j in 0u8..32 {
            p.push(prefix.wrapping_add(j).wrapping_add(1));
        }
        let _ = ac.insert(&p);
    }

    let needle = b"NEEDLE_THAT_SHOULD_FAIL_TO_INSERT";
    let result = ac.insert(needle);
    assert!(
        result.is_err(),
        "trie was meant to be full; insert(needle) should have returned Err but returned Ok"
    );
}

/// An unsigned (or wrong-key) mgmt packet must not be dispatched —
/// otherwise any UDP packet to the management port owns the security
/// policy. Verifies CRIT-3 stays fixed.
#[test]
fn mgmt_auth_rejects_unsigned_packet() {
    let key = [0x55u8; 16];
    let mut auth = MgmtAuth::new(key);
    let body = [0x04u8, 10, 0, 0, 7];
    let mut packet = vec![0u8; 8 + body.len() + 8];
    packet[..8].copy_from_slice(&1u64.to_be_bytes());
    packet[8..8 + body.len()].copy_from_slice(&body);
    assert!(
        auth.verify(&packet).is_none(),
        "MgmtAuth must reject a packet whose MAC region is unsigned"
    );
}

/// Replaying a recorded mgmt packet must not re-execute the command;
/// the counter has to advance monotonically.
#[test]
fn mgmt_auth_rejects_replayed_packet() {
    let key = [0x55u8; 16];
    let mut auth = MgmtAuth::new(key);
    let body = [0x01u8, 0x00, 0x50];
    let mut packet = [0u8; 32];
    let n = seal(&key, 7, &body, &mut packet).expect("buffer fits");
    assert!(auth.verify(&packet[..n]).is_some(), "first verify");
    assert!(
        auth.verify(&packet[..n]).is_none(),
        "replay of the same packet must be rejected"
    );
}

/// `checksum` indexes `data.len() - 1` as `usize`; passing an empty
/// slice underflows to `usize::MAX` and the loop runs off the buffer.
#[test]
fn checksum_handles_empty_slice_without_panicking() {
    let result = std::panic::catch_unwind(|| checksum(&[]));
    assert!(
        result.is_ok(),
        "checksum(&[]) panicked from data.len()-1 underflow"
    );
}
