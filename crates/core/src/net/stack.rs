//! The host's replies to ARP, ICMP echo and TCP connection requests.
//!
//! Each reply is built in place from its request. Anything not answered
//! has its payload handed on for inspection.

use core::net::Ipv4Addr;

use crate::config::{IP_ADDR, MAC_ADDR};
use crate::net::PacketSink;
use crate::net::constants::{ArpOpcode, IcmpType, IpProtocol, arp, ethernet, icmp, ipv4, tcp};
use crate::net::frame::{self, Frame, Ipv4Packet, Layout, Ports, TcpHeader, Transport};
use crate::net::tcp::TcpFlags;
use crate::security::hash::secret_key;

secret_key! {
    /// Per-boot secret keying the SYN-cookie PRF, so a cookie cannot be
    /// derived from packet headers or reused across reboots.
    SynCookieSecret
}

impl SynCookieSecret {
    /// Wraps 16 bytes of entropy into a secret. The caller is
    /// responsible for ensuring the bytes vary across reboots.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Computes the 32-bit SYN-cookie sequence number for the given
    /// 5-tuple. Uses SipHash-2-4 keyed by `self.0`, so the cookie is
    /// unforgeable to anyone who does not hold the secret.
    pub fn cookie(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> u32 {
        let mut buf = [0u8; 12];
        buf[..4].copy_from_slice(&src_ip.octets());
        buf[4..8].copy_from_slice(&dst_ip.octets());
        buf[8..10].copy_from_slice(&src_port.to_be_bytes());
        buf[10..12].copy_from_slice(&dst_port.to_be_bytes());
        self.hash(&buf) as u32
    }
}

/// Answers what `packet` asks of this host and returns the payload to
/// inspect, or `None` when the stack answered it or it carries none.
///
/// ARP requests, ICMP echo requests and TCP connection requests (answered
/// with a SYN cookie) are turned into replies in place and sent through
/// `sink`: the kernel's NIC or the daemon's `AF_PACKET` socket.
pub fn process_packet<'a, S: PacketSink>(
    packet: &'a mut [u8],
    sink: &mut S,
    syn_secret: &SynCookieSecret,
) -> Option<&'a [u8]> {
    respond(frame::parse(packet).ok()?, sink, syn_secret)
}

/// [`process_packet`] for a frame already parsed.
pub fn respond<'a, S: PacketSink>(
    frame: Frame<'a>,
    sink: &mut S,
    syn_secret: &SynCookieSecret,
) -> Option<&'a [u8]> {
    match frame {
        Frame::Arp(frame) => {
            answer_arp(frame, sink);
            None
        }
        Frame::Ipv4(packet) => respond_ipv4(packet, sink, syn_secret),
        Frame::Other(_) => None,
    }
}

fn respond_ipv4<'a, S: PacketSink>(
    packet: Ipv4Packet<'a>,
    sink: &mut S,
    syn_secret: &SynCookieSecret,
) -> Option<&'a [u8]> {
    if packet.dst != IP_ADDR {
        return None;
    }
    match packet.transport {
        Transport::Icmp { message_type }
            if IcmpType::from_u8(message_type) == Some(IcmpType::EchoRequest) =>
        {
            answer_echo_request(packet, sink);
            None
        }
        Transport::Tcp(tcp) if tcp.flags.is_connection_request() => {
            answer_connection_request(packet, tcp, sink, syn_secret);
            None
        }
        _ => Some(packet.into_payload()),
    }
}

/// Replies to an ARP request for this host's address.
fn answer_arp<S: PacketSink>(frame: &mut [u8], sink: &mut S) {
    const MAC: usize = ethernet::MAC_ADDR_SIZE;
    const IP: usize = ipv4::IP_ADDR_SIZE;
    let Some(packet) = frame.first_chunk_mut::<{ arp::MIN_PACKET_SIZE }>() else {
        return;
    };
    if !is_request_for_us(packet) {
        return;
    }
    let mut peer_mac = [0u8; MAC];
    peer_mac.copy_from_slice(&packet[ethernet::SRC_MAC_OFFSET..][..MAC]);
    let mut peer_ip = [0u8; IP];
    peer_ip.copy_from_slice(&packet[arp::SENDER_IP_OFFSET..][..IP]);

    packet[..MAC].copy_from_slice(&peer_mac);
    packet[ethernet::SRC_MAC_OFFSET..][..MAC].copy_from_slice(&MAC_ADDR);
    packet[arp::OPCODE_OFFSET..][..2].copy_from_slice(&(ArpOpcode::Reply as u16).to_be_bytes());
    packet[arp::SENDER_MAC_OFFSET..][..MAC].copy_from_slice(&MAC_ADDR);
    packet[arp::SENDER_IP_OFFSET..][..IP].copy_from_slice(&IP_ADDR.octets());
    packet[arp::TARGET_MAC_OFFSET..][..MAC].copy_from_slice(&peer_mac);
    packet[arp::TARGET_IP_OFFSET..][..IP].copy_from_slice(&peer_ip);
    sink.send(packet);
}

/// Whether `packet` is an Ethernet ARP request for this host's address.
fn is_request_for_us(packet: &[u8; arp::MIN_PACKET_SIZE]) -> bool {
    let u16_at = |offset: usize| u16::from_be_bytes([packet[offset], packet[offset + 1]]);
    u16_at(arp::HW_TYPE_OFFSET) == arp::HW_TYPE_ETHERNET
        && ArpOpcode::from_u16(u16_at(arp::OPCODE_OFFSET)) == Some(ArpOpcode::Request)
        && packet[arp::TARGET_IP_OFFSET..][..ipv4::IP_ADDR_SIZE] == IP_ADDR.octets()
}

/// Turns an echo request into its reply in place and sends it.
fn answer_echo_request<S: PacketSink>(packet: Ipv4Packet<'_>, sink: &mut S) {
    let Layout { transport, end, .. } = packet.layout;
    let frame = packet.frame;
    let checksum_at = transport + icmp::CHECKSUM_OFFSET;
    swap_addresses(frame);
    frame[transport] = IcmpType::EchoReply as u8;
    frame[checksum_at..checksum_at + 2].copy_from_slice(&[0, 0]);
    let csum = checksum(&frame[transport..end]);
    frame[checksum_at..checksum_at + 2].copy_from_slice(&csum.to_be_bytes());
    finish_ipv4_header(frame, transport, end);
    sink.send(&frame[..end]);
}

/// Answers a connection request with a SYN-ACK whose sequence number is a
/// SYN cookie, so no connection state is kept until the peer acknowledges.
fn answer_connection_request<S: PacketSink>(
    packet: Ipv4Packet<'_>,
    tcp: TcpHeader,
    sink: &mut S,
    syn_secret: &SynCookieSecret,
) {
    let cookie = syn_secret.cookie(packet.src, packet.dst, tcp.ports.src, tcp.ports.dst);
    let start = packet.layout.transport;
    let reply_end = start + tcp::MIN_HEADER_SIZE;
    let frame = packet.frame;
    swap_addresses(frame);
    // Sequence numbers wrap (RFC 793 §3.3): seq 0xFFFFFFFF acks as 0.
    let header = syn_ack_header(tcp.ports, cookie, tcp.seq.wrapping_add(1));
    frame[start..reply_end].copy_from_slice(&header);
    let csum = tcp_checksum(frame, start..reply_end);
    frame[start + tcp::CHECKSUM_OFFSET..start + tcp::CHECKSUM_OFFSET + 2]
        .copy_from_slice(&csum.to_be_bytes());
    finish_ipv4_header(frame, start, reply_end);
    sink.send(&frame[..reply_end]);
}

/// The 20-byte SYN-ACK header answering a segment between `ports`, with
/// its checksum left zero.
fn syn_ack_header(ports: Ports, seq: u32, ack: u32) -> [u8; tcp::MIN_HEADER_SIZE] {
    /// The receive window advertised; the SYN-cookie path keeps no
    /// per-flow state, so it is fixed.
    const REPLY_WINDOW: u16 = 64240;
    /// Header length encoded in the data-offset nibble (5 × 4 = 20 bytes).
    const DATA_OFFSET_5: u16 = 5 << 12;

    let data_offset_and_flags = DATA_OFFSET_5 | u16::from(TcpFlags::SYN_ACK.bits());
    let mut header = [0u8; tcp::MIN_HEADER_SIZE];
    header[tcp::SRC_PORT_OFFSET..][..2].copy_from_slice(&ports.dst.to_be_bytes());
    header[tcp::DST_PORT_OFFSET..][..2].copy_from_slice(&ports.src.to_be_bytes());
    header[tcp::SEQ_OFFSET..][..4].copy_from_slice(&seq.to_be_bytes());
    header[tcp::ACK_OFFSET..][..4].copy_from_slice(&ack.to_be_bytes());
    header[tcp::DATA_OFFSET_OFFSET..][..2].copy_from_slice(&data_offset_and_flags.to_be_bytes());
    header[tcp::WINDOW_OFFSET..][..2].copy_from_slice(&REPLY_WINDOW.to_be_bytes());
    header
}

/// Turns a received frame around: the sender's MAC and IP become the
/// destination, ours the source.
fn swap_addresses(packet: &mut [u8]) {
    let mut peer_mac = [0u8; ethernet::MAC_ADDR_SIZE];
    peer_mac.copy_from_slice(
        &packet[ethernet::SRC_MAC_OFFSET..ethernet::SRC_MAC_OFFSET + ethernet::MAC_ADDR_SIZE],
    );
    packet[..ethernet::MAC_ADDR_SIZE].copy_from_slice(&peer_mac);
    packet[ethernet::SRC_MAC_OFFSET..ethernet::SRC_MAC_OFFSET + ethernet::MAC_ADDR_SIZE]
        .copy_from_slice(&MAC_ADDR);

    let mut peer_ip = [0u8; ipv4::IP_ADDR_SIZE];
    peer_ip.copy_from_slice(&packet[ipv4::SRC_IP_OFFSET..ipv4::SRC_IP_OFFSET + ipv4::IP_ADDR_SIZE]);
    packet[ipv4::SRC_IP_OFFSET..ipv4::SRC_IP_OFFSET + ipv4::IP_ADDR_SIZE]
        .copy_from_slice(&IP_ADDR.octets());
    packet[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE].copy_from_slice(&peer_ip);
}

/// Sets the total length and a fresh TTL on an outgoing IPv4 datagram
/// whose transport header starts at frame offset `transport` and which ends
/// at `end`, then recomputes its header checksum.
fn finish_ipv4_header(frame: &mut [u8], transport: usize, end: usize) {
    const TOTAL_LEN: usize = ipv4::HEADER_OFFSET + ipv4::field::TOTAL_LEN;
    const TTL: usize = ipv4::HEADER_OFFSET + ipv4::field::TTL;
    const CHECKSUM: usize = ipv4::HEADER_OFFSET + ipv4::field::CHECKSUM;
    let total_len = (end - ipv4::HEADER_OFFSET) as u16;
    frame[TOTAL_LEN..][..2].copy_from_slice(&total_len.to_be_bytes());
    frame[TTL] = ipv4::DEFAULT_TTL;
    frame[CHECKSUM..][..2].copy_from_slice(&[0, 0]);
    let csum = checksum(&frame[ipv4::HEADER_OFFSET..transport]);
    frame[CHECKSUM..][..2].copy_from_slice(&csum.to_be_bytes());
}

/// TCP checksum of the segment at `segment`, over the IPv4 pseudo-header
/// built from the addresses already written into `packet`.
fn tcp_checksum(packet: &[u8], segment: core::ops::Range<usize>) -> u16 {
    let mut sum: u32 = 0;
    let mut add = |bytes: &[u8]| {
        let (pairs, rest) = bytes.as_chunks::<2>();
        for pair in pairs {
            sum += u32::from(u16::from_be_bytes(*pair));
        }
        if let [last] = rest {
            sum += u32::from(*last) << 8;
        }
    };
    add(&packet[ipv4::SRC_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE]);
    add(&[0, IpProtocol::Tcp as u8]);
    add(&(segment.len() as u16).to_be_bytes());
    add(&packet[segment]);
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Calculates the Internet checksum for protocol headers.
///
/// Implements the standard one's complement checksum algorithm.
pub const fn checksum(data: &[u8]) -> u16 {
    // The loop condition uses `data.len() - 1`, which would underflow
    // to usize::MAX on an empty slice and run off into unmapped memory.
    // Empty input has no bytes to fold, so the one's complement of the
    // empty sum (0) is 0xFFFF.
    if data.is_empty() {
        return 0xFFFF;
    }
    let mut sum: u32 = 0;
    let mut i = 0;
    while i < data.len() - 1 {
        sum += ((data[i] as u32) << 8) | (data[i + 1] as u32);
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}
