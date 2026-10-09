//! Replies the network stack generates must be frames a real host accepts.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{CaptureSink, PEER_IP, icmp_echo_with_payload, tcp};
use sec_core::net::stack::{SynCookieSecret, checksum, process_packet};

fn reply_to(mut frame: Vec<u8>) -> Vec<u8> {
    let mut sink = CaptureSink::default();
    let _ = process_packet(&mut frame, &mut sink, &SynCookieSecret::new([3; 16]));
    assert_eq!(sink.sent.len(), 1, "expected exactly one reply");
    sink.sent.pop().unwrap()
}

fn ip_total_len(frame: &[u8]) -> usize {
    usize::from(u16::from_be_bytes([frame[16], frame[17]]))
}

fn ip_header_len(frame: &[u8]) -> usize {
    usize::from(frame[14] & 0x0F) * 4
}

/// One's-complement sum over `data` folds to 0 when its checksum is right.
const fn sums_to_zero(data: &[u8]) -> bool {
    checksum(data) == 0
}

#[test]
fn echo_reply_carries_the_whole_request_payload() {
    let request = icmp_echo_with_payload(PEER_IP, &[0x5A; 400]);

    let reply = reply_to(request.clone());

    assert_eq!(reply.len(), request.len());
    assert_eq!(&reply[42..], &request[42..], "echo data must be returned unchanged");
}

#[test]
fn echo_reply_has_valid_ip_and_icmp_checksums() {
    let reply = reply_to(icmp_echo_with_payload(PEER_IP, &[0x5A; 400]));

    let ihl = ip_header_len(&reply);
    assert_eq!(ip_total_len(&reply), reply.len() - 14);
    assert!(sums_to_zero(&reply[14..14 + ihl]), "bad IPv4 header checksum");
    assert!(sums_to_zero(&reply[14 + ihl..]), "bad ICMP checksum");
}

#[test]
fn syn_ack_has_valid_lengths_and_checksums() {
    let reply = reply_to(tcp(PEER_IP, 4444, 80, 0x02, b""));

    let ihl = ip_header_len(&reply);
    let segment = &reply[14 + ihl..];
    assert_eq!(ip_total_len(&reply), reply.len() - 14);
    assert!(sums_to_zero(&reply[14..14 + ihl]), "bad IPv4 header checksum");
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&reply[26..34]);
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&u16::try_from(segment.len()).unwrap().to_be_bytes());
    pseudo.extend_from_slice(segment);
    assert!(sums_to_zero(&pseudo), "bad TCP checksum");
}

#[test]
fn syn_with_options_gets_a_syn_ack_sized_to_its_own_header() {
    let mut syn = tcp(PEER_IP, 4444, 80, 0x02, &[2, 4, 5, 0xB4, 1, 1, 1, 0]);
    syn[14 + 20 + 12] = 0x70;

    let reply = reply_to(syn);

    assert_eq!(ip_total_len(&reply), 20 + 20);
    assert_eq!(reply.len(), 14 + 20 + 20);
}
