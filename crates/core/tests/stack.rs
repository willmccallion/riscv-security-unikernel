//! The network stack's replies and hand-offs: SYN cookies, which packets
//! it answers, and what it refuses.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation
)]

mod common;

use common::{CaptureSink, arp_request, tcp_segment};
use sec_core::config::{IP_ADDR as KERNEL_IP, MAC_ADDR as KERNEL_MAC};
use sec_core::net::constants::{arp, ethernet, ipv4, tcp};
use sec_core::net::stack::{SynCookieSecret, checksum, process_packet};
use sec_core::net::tcp::TcpFlags;

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

/// Two SYN segments that share `(src_ip, src_port)` but target
/// different destination ports must produce different SYN-ACK
/// sequence numbers. A trivial cookie that ignores the destination
/// port lets an attacker compute valid replies for any port given a
/// single observation.
#[test]
fn syn_cookie_depends_on_destination_port() {
    let mut sink_a = CaptureSink::default();
    let mut sink_b = CaptureSink::default();

    let mut frame_a = tcp_segment([10, 0, 0, 7], (4444, 80), TcpFlags::SYN, 0xDEAD_BEEF, &[]);
    let mut frame_b = tcp_segment([10, 0, 0, 7], (4444, 443), TcpFlags::SYN, 0xDEAD_BEEF, &[]);

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
    let mut frame = tcp_segment(src, (src_port, 80), TcpFlags::SYN, 0, &[]);

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

const fn read_flags(frame: &[u8]) -> TcpFlags {
    let tcp_off = ethernet::MIN_FRAME_SIZE + ipv4::MIN_HEADER_SIZE;
    TcpFlags::new(frame[tcp_off + tcp::FLAGS_OFFSET])
}

/// `process_packet` must hand TCP application bytes back to the
/// caller for inspection on every non-SYN segment; otherwise the DPI
/// engine never sees TCP traffic.
#[test]
fn non_syn_tcp_returns_payload_to_caller() {
    let mut sink = CaptureSink::default();
    let payload = b"GET / HTTP/1.1\r\nDROP TABLE users--";
    let mut frame = tcp_segment([10, 0, 0, 5], (1024, 80), TcpFlags::ACK, 1, payload);

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

/// Regression: a SYN with `seq == u32::MAX` must wrap the ACK number
/// rather than panic on `seq + 1`. Found by the cargo-fuzz
/// `process_packet` target during Checkpoint E.
#[test]
fn process_packet_handles_syn_with_max_seq_without_panicking() {
    let mut sink = CaptureSink::default();
    let mut frame = tcp_segment([10, 0, 0, 5], (4444, 80), TcpFlags::SYN, u32::MAX, &[]);
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
    let mut frame = tcp_segment([10, 0, 0, 5], (4444, 80), TcpFlags::SYN, 0, &[]);
    let secret = test_syn_secret();
    let _ = process_packet(&mut frame, &mut sink, &secret);
    assert_eq!(sink.sent.len(), 1, "SYN must produce SYN-ACK");
    let flags = read_flags(&sink.sent[0]);
    assert!(flags.contains(TcpFlags::SYN_ACK));
}

/// A SYN-ACK is the answer to a connection request only: a segment with
/// SYN plus ACK, FIN or RST is not one, and answering it would reflect
/// traffic at whoever the source address names.
#[test]
fn process_packet_answers_only_bare_syns_with_a_syn_ack() {
    for flags in [
        TcpFlags::SYN_ACK,
        TcpFlags::SYN | TcpFlags::FIN,
        TcpFlags::SYN | TcpFlags::RST,
    ] {
        let mut sink = CaptureSink::default();
        let mut frame = tcp_segment([10, 0, 0, 5], (4444, 80), flags, 0, &[]);

        let _ = process_packet(&mut frame, &mut sink, &test_syn_secret());

        assert!(sink.sent.is_empty(), "flags {flags:?} got a reply");
    }
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
    let ip_total = IHL_BYTES + tcp::MIN_HEADER_SIZE;
    frame[ipv4::TOTAL_LENGTH_OFFSET..ipv4::TOTAL_LENGTH_OFFSET + 2]
        .copy_from_slice(&u16::try_from(ip_total).unwrap().to_be_bytes());
    frame[ipv4::PROTOCOL_OFFSET] = 6;
    frame[ipv4::SRC_IP_OFFSET..ipv4::SRC_IP_OFFSET + 4].copy_from_slice(&[10, 0, 0, 5]);
    frame[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + 4].copy_from_slice(&KERNEL_IP.octets());

    let tcp_off = ethernet::MIN_FRAME_SIZE + IHL_BYTES;
    let src_port: u16 = 4444;
    let dst_port: u16 = 80;
    frame[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    frame[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    frame[tcp_off + 4..tcp_off + 8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    frame[tcp_off + 12] = 5 << 4;
    frame[tcp_off + 13] = TcpFlags::SYN.bits();

    let mut sink = CaptureSink::default();
    let secret = test_syn_secret();
    let _ = process_packet(&mut frame, &mut sink, &secret);

    assert_eq!(sink.sent.len(), 1, "SYN with IHL=9 must produce SYN-ACK");
    let reply = &sink.sent[0];
    let reply_tcp_off = ethernet::MIN_FRAME_SIZE + IHL_BYTES;
    let flags = TcpFlags::new(reply[reply_tcp_off + tcp::FLAGS_OFFSET]);
    assert!(flags.contains(TcpFlags::SYN_ACK));
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
    let mut frame = tcp_segment([10, 0, 0, 5], (4444, 80), TcpFlags::SYN, 0, &[]);
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
    let mut frame = tcp_segment([10, 0, 0, 5], (4444, 80), TcpFlags::ACK, 1, b"payload");
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
    let mut frame = tcp_segment([10, 0, 0, 5], (4444, 80), TcpFlags::SYN, 0, &[]);
    frame[ipv4::VERSION_IHL_OFFSET] = 0x65; // version=6, ihl=5
    let mut sink = CaptureSink::default();
    let secret = test_syn_secret();
    let result = process_packet(&mut frame, &mut sink, &secret);
    assert!(
        sink.sent.is_empty(),
        "version!=4 must not generate any reply"
    );
    assert!(result.is_none(), "version!=4 must not return a payload");
}

/// The ARP hardware-type field sits 14 bytes into a standard
/// Ethernet+ARP frame (immediately after the Ethernet header). Any
/// other offset means the parser is reading a different field
/// entirely.
#[test]
fn arp_hw_type_offset_matches_wire_layout() {
    assert_eq!(
        arp::HW_TYPE_OFFSET,
        14,
        "ARP hw_type lives at offset 14 of the Ethernet frame, not {}",
        arp::HW_TYPE_OFFSET
    );
}

/// An ARP request whose hardware-type field is not Ethernet (1) must
/// not produce a reply.
#[test]
fn arp_request_with_non_ethernet_hw_type_is_ignored() {
    let mut sink = CaptureSink::default();
    let mut frame = arp_request(0xFFFF, KERNEL_IP.octets());
    let secret = test_syn_secret();
    let _ = process_packet(&mut frame, &mut sink, &secret);
    assert!(
        sink.sent.is_empty(),
        "ARP with hw_type=0xFFFF should not generate a reply"
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
