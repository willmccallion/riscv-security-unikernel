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
use sec_core::net::constants::{arp, ethernet, ipv4, tcp};
use sec_core::net::stack::{SynCookieSecret, checksum, process_packet};
use sec_core::net::tcp::{TCP_ACK, TCP_SYN, extract_ports};
use sec_core::security::alert::should_emit_ddos_alert;
use sec_core::security::dos::PenaltyBox;
use sec_core::security::dpi::{AhoCorasick, DynRulesError, DynamicRules};
use sec_core::security::firewall::{FirewallError, FirewallState};
use sec_core::security::flow::FlowTable;
use sec_core::security::heuristic::HeuristicEngine;
use sec_core::security::mgmt_auth::{MgmtAuth, seal};
use sec_core::security::vm::{
    Instruction, VM, VmAction, VmError, VmRuntimeError, validate as validate_vm,
};

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
const fn test_syn_secret() -> SynCookieSecret {
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
    const PUBLIC_MAGIC: u32 = 0xCAFE_BABE;
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
        .wrapping_add(PUBLIC_MAGIC);
    assert_ne!(
        seq, trivial,
        "cookie equals src_ip[3] + src_port + magic; needs a per-boot secret"
    );
}

const fn read_seq(frame: &[u8]) -> u32 {
    let tcp_off = ethernet::MIN_FRAME_SIZE + ipv4::MIN_HEADER_SIZE;
    u32::from_be_bytes([
        frame[tcp_off + 4],
        frame[tcp_off + 5],
        frame[tcp_off + 6],
        frame[tcp_off + 7],
    ])
}

const fn read_flags(frame: &[u8]) -> u16 {
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

/// `extract_ports` is the helper the kernel uses to read
/// the destination port before invoking `process_packet`, so it must
/// produce the right values for raw TCP segments.
#[test]
fn extract_ports_reads_dst_port_from_raw_tcp_segment() {
    let frame = build_tcp_frame([10, 0, 0, 5], 4444, 23, TCP_SYN, 0, &[]);
    let l4_offset = ethernet::MIN_FRAME_SIZE + ipv4::MIN_HEADER_SIZE;
    let (sp, dp) =
        extract_ports(&frame[l4_offset..]).expect("ports must extract from frame");
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

/// Regression: the SYN-ACK reply path must work when the TCP header
/// sits at an offset that is not 4-byte aligned within the frame
/// buffer. IHL=9 puts a 36-byte IP header in the frame, which lands
/// the TCP header at byte 50 — odd-aligned relative to the start of
/// the IP header. Byte-wise parsing must behave exactly as on the
/// IHL=5 path.
#[test]
fn process_packet_handles_syn_with_extended_ip_options() {
    const IHL_WORDS: usize = 9;
    const IHL_BYTES: usize = IHL_WORDS * 4;
    let total = ethernet::MIN_FRAME_SIZE + IHL_BYTES + tcp::MIN_HEADER_SIZE;
    let mut frame = vec![0u8; total];

    frame[0..6].copy_from_slice(&KERNEL_MAC);
    frame[6..12].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    frame[ethernet::TYPE_OFFSET] = 0x08;
    frame[ethernet::TYPE_OFFSET + 1] = 0x00;

    frame[ipv4::VERSION_IHL_OFFSET] = 0x40 | (IHL_WORDS as u8);
    frame[ipv4::PROTOCOL_OFFSET] = 6;
    frame[ipv4::SRC_IP_OFFSET..ipv4::SRC_IP_OFFSET + 4].copy_from_slice(&[10, 0, 0, 5]);
    frame[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + 4].copy_from_slice(&KERNEL_IP);

    let tcp_off = ethernet::MIN_FRAME_SIZE + IHL_BYTES;
    let src_port: u16 = 4444;
    let dst_port: u16 = 80;
    frame[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[tcp_off + 4..tcp_off + 8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    let dof = (5u16 << 12) | TCP_SYN;
    frame[tcp_off + 12..tcp_off + 14].copy_from_slice(&dof.to_be_bytes());

    let mut sink = CaptureSink::default();
    let secret = test_syn_secret();
    let _ = process_packet(&mut frame, &mut sink, &secret);

    assert_eq!(sink.sent.len(), 1, "SYN with IHL=9 must produce SYN-ACK");
    let reply = &sink.sent[0];
    let reply_tcp_off = ethernet::MIN_FRAME_SIZE + IHL_BYTES;
    let flags = u16::from_be_bytes([reply[reply_tcp_off + 12], reply[reply_tcp_off + 13]]) & 0x003F;
    assert_eq!(flags & (TCP_SYN | TCP_ACK), TCP_SYN | TCP_ACK);
    let reply_src = u16::from_be_bytes([reply[reply_tcp_off], reply[reply_tcp_off + 1]]);
    let reply_dst = u16::from_be_bytes([reply[reply_tcp_off + 2], reply[reply_tcp_off + 3]]);
    assert_eq!(reply_src, dst_port);
    assert_eq!(reply_dst, src_port);
}

/// A packet with `IHL < 5` lets the sender push the "TCP header"
/// inside the IP header, which would let downstream port-based
/// firewall rules match against header bytes instead of the real
/// destination port. `process_packet` must drop these.
#[test]
fn process_packet_rejects_ipv4_with_ihl_less_than_5() {
    let mut frame = build_tcp_frame([10, 0, 0, 5], 4444, 80, TCP_SYN, 0, &[]);
    frame[ipv4::VERSION_IHL_OFFSET] = 0x40; // version=4, ihl=0
    let mut sink = CaptureSink::default();
    let secret = test_syn_secret();
    let result = process_packet(&mut frame, &mut sink, &secret);
    assert!(sink.sent.is_empty(), "IHL=0 must not generate any reply");
    assert!(result.is_none(), "IHL=0 must not return a payload");
}

/// Same shape as the IHL check, applied to the TCP data offset:
/// a `data_offset < 5` would put the "TCP payload" inside the TCP
/// header, evading DPI / firewall inspection on the real bytes.
#[test]
fn process_packet_rejects_tcp_with_data_offset_less_than_5() {
    let mut frame = build_tcp_frame([10, 0, 0, 5], 4444, 80, TCP_ACK, 1, b"payload");
    let tcp_off = ethernet::MIN_FRAME_SIZE + ipv4::MIN_HEADER_SIZE;
    // Data offset = 0, flags preserved.
    frame[tcp_off + 12] = 0x00;
    let mut sink = CaptureSink::default();
    let secret = test_syn_secret();
    let result = process_packet(&mut frame, &mut sink, &secret);
    assert!(result.is_none(), "data_offset=0 must not yield a payload");
}

/// A packet with IP version != 4 (e.g. someone sending IPv6 bytes
/// through the IPv4 `EtherType`, or just garbage) must be dropped
/// rather than silently parsed as IPv4.
#[test]
fn process_packet_rejects_ipv4_with_wrong_version() {
    let mut frame = build_tcp_frame([10, 0, 0, 5], 4444, 80, TCP_SYN, 0, &[]);
    frame[ipv4::VERSION_IHL_OFFSET] = 0x65; // version=6, ihl=5
    let mut sink = CaptureSink::default();
    let secret = test_syn_secret();
    let result = process_packet(&mut frame, &mut sink, &secret);
    assert!(sink.sent.is_empty(), "version!=4 must not generate any reply");
    assert!(result.is_none(), "version!=4 must not return a payload");
}

/// `DynamicRules::add` used to return `()` and silently drop on
/// overflow, so an operator who hit the 8-pattern cap saw no error
/// and believed their pattern was loaded. The fix returns a Result
/// that the mgmt ack reports; this test pins the new
/// signalling so a future "make it return () again" refactor fails
/// loudly.
#[test]
fn dynamic_rules_overflow_is_signalled() {
    let mut rules = DynamicRules::new();
    for i in 0..8 {
        let pat = [b'a' + i as u8; 4];
        assert!(rules.add(&pat).is_ok(), "first 8 patterns must fit");
    }
    let result = rules.add(b"ninth");
    assert_eq!(result, Err(DynRulesError::Full));
    let too_long = [0u8; 33];
    assert_eq!(
        DynamicRules::new().add(&too_long),
        Err(DynRulesError::TooLong)
    );
}

/// `DynamicRules::add` had no dedup, so an authenticated attacker
/// could send `AddDpiPattern(X)` 8 times and fill every slot with
/// duplicates of the same signature, wedging the 8-slot table
/// against further legitimate patterns. The fix treats a duplicate
/// add as a no-op so one logical pattern consumes one slot.
#[test]
fn dynamic_rules_dedups_duplicate_patterns() {
    let mut rules = DynamicRules::new();
    for _ in 0..8 {
        assert_eq!(rules.add(b"EICAR"), Ok(()));
    }
    // One slot consumed by EICAR — 7 more distinct patterns still fit.
    for i in 0..7u8 {
        let pat = [b'a' + i; 4];
        assert_eq!(
            rules.add(&pat),
            Ok(()),
            "distinct pattern {i} must still fit after duplicates"
        );
    }
    assert_eq!(rules.add(b"overflow"), Err(DynRulesError::Full));
    assert!(rules.check(b"xxEICARxx"));
}

/// An empty pattern must be rejected at add-time. The check path calls
/// `payload.windows(pat.len())`, and `slice::windows(0)` is defined to
/// panic; storing a zero-length pattern turns the next data-plane
/// packet into a kernel panic. Accepting `len=0` through the mgmt
/// dispatcher (which sources `len` from an attacker-controlled byte)
/// was a single-packet post-auth kill switch until this check landed.
#[test]
fn dynamic_rules_rejects_empty_pattern() {
    let mut rules = DynamicRules::new();
    assert_eq!(rules.add(&[]), Err(DynRulesError::Empty));
    // Empty pattern must not have been stored; a non-empty add after
    // it still succeeds and does not panic on `check`.
    assert!(rules.add(b"abc").is_ok());
    assert!(rules.check(b"xxabcxx"));
    assert!(!rules.check(b"xxxxxx"));
}

/// `PenaltyBox::ban` used to allocate a fresh slot even when the IP
/// was already banned, so an authenticated attacker sending
/// `BanIp(X)` 16 times with the same X filled every slot with
/// duplicates. The fix refreshes the existing entry in place so
/// duplicates consume one slot regardless of how many times they
/// arrive.
#[test]
fn penalty_box_dedups_duplicate_bans() {
    let mut pbox = PenaltyBox::new();
    let now = 1_000u64;
    let dur = 10_000u64;
    let target = [10, 0, 0, 1];

    for _ in 0..16 {
        pbox.ban(&target, dur, now);
    }
    assert!(pbox.is_banned(&target, now));

    // With dedup, 15 slots are still free — 15 further distinct bans
    // must all land without evicting `target`.
    for i in 2..17u8 {
        pbox.ban(&[10, 0, 0, i], dur, now);
    }
    assert!(
        pbox.is_banned(&target, now),
        "duplicate-ban dedup must not have evicted the first IP"
    );
    for i in 2..17u8 {
        assert!(pbox.is_banned(&[10, 0, 0, i], now));
    }
}

/// `FirewallState::block_port` used to return `()` and had no dedup,
/// so an authenticated attacker could send `BlockPort(P)` 16 times
/// and permanently wedge the table against further legitimate blocks
/// — overflow was silent and duplicates consumed all 16 slots. The
/// fix dedups and returns a Result that the mgmt ack reports.
#[test]
fn firewall_dedups_and_signals_overflow() {
    let mut fw = FirewallState::new();
    // Same port 16 times must only consume one slot.
    for _ in 0..16 {
        assert_eq!(fw.block_port(9000), Ok(()));
    }
    // A different port still fits — dedup worked.
    assert_eq!(fw.block_port(9001), Ok(()));
    assert!(fw.is_blocked(9000));
    assert!(fw.is_blocked(9001));

    // Fill the remaining 14 slots with distinct ports, then confirm
    // the next distinct port overflows visibly.
    for p in 0..14u16 {
        assert_eq!(fw.block_port(10_000 + p), Ok(()));
    }
    assert_eq!(fw.block_port(30_000), Err(FirewallError::Full));
    // An already-blocked port still returns Ok even when full.
    assert_eq!(fw.block_port(9000), Ok(()));
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
        let _ = vm.execute(&prog, &[0u8; 64]);
    }));

    assert!(
        result.is_ok(),
        "VM panicked on instruction with reg_a >= 16"
    );
}

/// `validate` must reject any program whose opcode byte is not one of
/// the variants the VM explicitly handles. Without this check unknown
/// opcodes hit the `_ => {}` arm in `execute` and become silent
/// no-ops, which lets an attacker probe the upload path without
/// rejection and means a future opcode added at an unused value
/// would silently change behaviour for older programs.
#[test]
fn vm_rejects_unknown_opcode() {
    let prog = [Instruction::new(0xFF, 0, 0, 0)];
    assert_eq!(validate_vm(&prog), Err(VmError::InvalidOpcode));
}

/// A jump instruction with a target far beyond the end of the program
/// must terminate cleanly rather than running off into uninitialised
/// memory or panicking.
#[test]
fn vm_rejects_out_of_range_jump_target() {
    let prog = [Instruction::new(0x0A, 0, 0, u32::MAX)];
    let mut vm = VM::new();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = vm.execute(&prog, &[0u8; 64]);
    }));

    assert!(
        result.is_ok(),
        "VM panicked on a jump with an out-of-range target"
    );
}

/// A one-instruction infinite loop (`Jmp 0`) passes `validate` but must
/// trip the cycle budget and surface `Timeout` to the caller rather
/// than silently returning pass. The old contract defaulted to `1`
/// (pass) on cycle exhaustion, which let an authenticated attacker
/// upload a program that taxed every packet ~1000× without any alert.
#[test]
fn vm_reports_timeout_on_infinite_loop() {
    let prog = [Instruction::new(0x0A, 0, 0, 0)];
    assert!(validate_vm(&prog).is_ok(), "Jmp 0 must pass validation");
    let mut vm = VM::new();
    assert_eq!(vm.execute(&prog, &[0u8; 64]), Err(VmRuntimeError::Timeout));
}

/// `Ret` with an immediate that is not 0 (drop) or 1 (pass) must
/// surface as `InvalidAction` rather than being coerced to pass. The
/// old caller treated every non-zero value as pass, so a program
/// ending in `Ret 0xDEADBEEF` silently passed and any future action-
/// code extension would silently mis-interpret it.
#[test]
fn vm_reports_invalid_action_on_unknown_ret_immediate() {
    let prog = [Instruction::new(0x0D, 0, 0, 0xDEAD_BEEF)];
    let mut vm = VM::new();
    assert_eq!(
        vm.execute(&prog, &[0u8; 64]),
        Err(VmRuntimeError::InvalidAction(0xDEAD_BEEF))
    );
}

/// Ret 0 → Drop, Ret 1 → Pass, round-trip both.
#[test]
fn vm_returns_typed_actions_for_valid_ret_immediates() {
    let drop_prog = [Instruction::new(0x0D, 0, 0, 0)];
    let pass_prog = [Instruction::new(0x0D, 0, 0, 1)];
    let mut vm = VM::new();
    assert_eq!(vm.execute(&drop_prog, &[0u8; 64]), Ok(VmAction::Drop));
    assert_eq!(vm.execute(&pass_prog, &[0u8; 64]), Ok(VmAction::Pass));
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
    auth.set_epoch(0x1234_5678);
    let body = [0x04u8, 10, 0, 0, 7];
    let mut packet = vec![0u8; 8 + body.len() + 8];
    packet[..8].copy_from_slice(&((0x1234_5678u64 << 32) | 1).to_be_bytes());
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
    let epoch: u32 = 0x1234_5678;
    auth.set_epoch(epoch);
    let body = [0x01u8, 0x00, 0x50];
    let mut packet = [0u8; 32];
    let n = seal(&key, ((epoch as u64) << 32) | 7, &body, &mut packet).expect("buffer fits");
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

/// The first DDoS drop must fire an alert. The naive `count % N == 0`
/// rule swallows it because `1 % N == 1`, so an attack can dump
/// `N - 1` packets before any alert reaches the operator.
#[test]
fn ddos_alert_fires_on_first_drop() {
    assert!(should_emit_ddos_alert(1, 50), "first drop must alert");
    assert!(!should_emit_ddos_alert(2, 50));
    assert!(!should_emit_ddos_alert(49, 50));
    assert!(should_emit_ddos_alert(50, 50));
    assert!(should_emit_ddos_alert(100, 50));
    // sample_rate of 0 should not be a div-by-zero; treat as "alert always".
    assert!(should_emit_ddos_alert(1, 0));
    assert!(should_emit_ddos_alert(99, 0));
}

#[test]
fn firewall_unblock_removes_only_that_port() {
    let mut fw = FirewallState::new();
    for port in [22, 23, 80] {
        fw.block_port(port).unwrap();
    }

    fw.unblock_port(23);

    assert!(fw.is_blocked(22) && !fw.is_blocked(23) && fw.is_blocked(80));
}

#[test]
fn firewall_unblock_frees_a_slot_in_a_full_table() {
    let mut fw = FirewallState::new();
    for port in 0..16 {
        fw.block_port(port).unwrap();
    }

    fw.unblock_port(5);

    assert_eq!(fw.block_port(100), Ok(()));
}

#[test]
fn dynamic_rules_remove_deletes_only_that_pattern() {
    let mut rules = DynamicRules::new();
    rules.add(b"alpha").unwrap();
    rules.add(b"beta").unwrap();
    rules.add(b"gamma").unwrap();

    rules.remove(b"beta");

    assert!(rules.check(b"xx alpha xx") && !rules.check(b"xx beta xx") && rules.check(b"gamma"));
}

#[test]
fn penalty_box_unban_lifts_an_active_ban() {
    let mut pbox = PenaltyBox::new();
    pbox.ban(&[10, 0, 0, 1], 1_000, 0);

    pbox.unban(&[10, 0, 0, 1]);

    assert!(!pbox.is_banned(&[10, 0, 0, 1], 1));
}

#[test]
fn vm_program_finishing_on_its_last_allowed_step_is_not_a_timeout() {
    let program = [Instruction::new(0x00, 0, 0, 0); 1000];

    let action = VM::new().execute(&program, &[]);

    assert_eq!(action, Ok(VmAction::Pass));
}

#[test]
fn vm_out_of_bounds_loads_all_clear_the_register() {
    // Each program loads 0xFF into r0, then loads from past the end of a
    // 2-byte packet and returns r0 == 0 ? pass : drop.
    for load in [0x01u8, 0x02, 0x03] {
        let program = [
            Instruction::new(0x04, 0, 0, 0xFF),
            Instruction::new(load, 0, 0, 2),
            Instruction::new(0x04, 1, 0, 0),
            Instruction::new(0x06, 0, 1, 0),
            Instruction::new(0x0B, 0, 0, 6),
            Instruction::new(0x0D, 0, 0, 0),
            Instruction::new(0x0D, 0, 0, 1),
        ];

        let action = VM::new().execute(&program, &[0xAB, 0xCD]);

        assert_eq!(action, Ok(VmAction::Pass), "opcode {load:#x} left a stale register");
    }
}

#[test]
fn penalty_box_ban_near_the_end_of_time_does_not_overflow() {
    let mut pbox = PenaltyBox::new();

    pbox.ban(&[10, 0, 0, 1], u64::MAX, u64::MAX - 5);

    assert!(pbox.is_banned(&[10, 0, 0, 1], u64::MAX - 1));
}

#[test]
fn penalty_box_reuses_a_ban_ending_now_before_evicting_an_active_one() {
    let mut pbox = PenaltyBox::new();
    for i in 0..15u8 {
        pbox.ban(&[10, 0, 0, i], 1_000, 0);
    }
    pbox.ban(&[10, 0, 0, 15], 100, 0);

    pbox.ban(&[10, 0, 1, 1], 100, 100);

    assert!(pbox.is_banned(&[10, 0, 0, 0], 100), "an active ban was evicted");
}
