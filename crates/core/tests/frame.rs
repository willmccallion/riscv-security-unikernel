//! Parsing received frames in `sec_core::net::frame`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{PEER_IP, icmp_echo_with_payload, ipv4, tcp, udp};
use core::net::Ipv4Addr;
use sec_core::config::IP_ADDR;
use sec_core::net::frame::{self, Frame, Ipv4Packet, Ports, Rejection, Transport};
use sec_core::net::tcp::TcpFlags;

fn parse_ipv4(frame: &mut [u8]) -> Ipv4Packet<'_> {
    match frame::parse(frame) {
        Ok(Frame::Ipv4(packet)) => packet,
        other => panic!("not a parsed IPv4 packet: {other:?}"),
    }
}

#[test]
fn a_tcp_segment_yields_its_addresses_ports_flags_and_sequence() {
    let mut frame = tcp(PEER_IP, 4444, 23, 0x12, b"data");
    frame[38..42].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());

    let packet = parse_ipv4(&mut frame);

    assert_eq!(packet.src, Ipv4Addr::from(PEER_IP));
    assert_eq!(packet.dst, IP_ADDR);
    let Transport::Tcp(tcp) = packet.transport else {
        panic!("not TCP: {:?}", packet.transport);
    };
    assert_eq!(tcp.ports, Ports { src: 4444, dst: 23 });
    assert_eq!(tcp.flags, TcpFlags::SYN_ACK);
    assert_eq!(tcp.seq, 0xDEAD_BEEF);
    assert_eq!(packet.payload(), b"data");
}

#[test]
fn a_tcp_payload_ends_at_the_ip_total_length() {
    let mut frame = tcp(PEER_IP, 4444, 80, 0x18, b"data");
    frame.extend_from_slice(b"padding");

    assert_eq!(parse_ipv4(&mut frame).payload(), b"data");
}

#[test]
fn a_udp_payload_ends_at_the_udp_length() {
    let mut frame = udp(PEER_IP, 5000, 53, b"query and more");
    frame[38..40].copy_from_slice(&(8u16 + 5).to_be_bytes());

    let packet = parse_ipv4(&mut frame);

    assert_eq!(
        packet.transport,
        Transport::Udp(Ports { src: 5000, dst: 53 })
    );
    assert_eq!(packet.payload(), b"query");
}

#[test]
fn an_icmp_message_is_its_whole_transport_section() {
    let mut frame = icmp_echo_with_payload(PEER_IP, b"ping");

    let packet = parse_ipv4(&mut frame);

    assert_eq!(packet.transport, Transport::Icmp { message_type: 8 });
    assert_eq!(packet.payload().len(), 8 + 4);
}

#[test]
fn another_protocol_has_no_ports() {
    let mut frame = ipv4(PEER_IP, 47, b"gre");

    let packet = parse_ipv4(&mut frame);

    assert_eq!(packet.transport, Transport::Other(47));
    assert_eq!(packet.transport.ports(), None);
    assert_eq!(packet.payload(), b"gre");
}

#[test]
fn a_fragment_is_rejected_with_its_header_fields() {
    let mut frame = udp(PEER_IP, 5000, 53, b"x");
    frame[20..22].copy_from_slice(&0x2000u16.to_be_bytes());

    let rejected = frame::parse(&mut frame).expect_err("a fragment");

    assert_eq!(rejected.reason, Rejection::Fragment);
    assert_eq!(rejected.src, Ipv4Addr::from(PEER_IP));
    assert_eq!(rejected.protocol, 17);
}

#[test]
fn an_arp_frame_is_handed_on_unparsed() {
    let mut frame = vec![0u8; 42];
    frame[12..14].copy_from_slice(&[0x08, 0x06]);

    assert!(matches!(frame::parse(&mut frame), Ok(Frame::Arp(_))));
}

#[test]
fn an_ipv4_frame_too_short_for_a_header_is_not_parsed_as_ipv4() {
    let mut frame = udp(PEER_IP, 5000, 53, b"");
    frame.truncate(14 + 19);

    assert!(matches!(frame::parse(&mut frame), Ok(Frame::Other(_))));
}
