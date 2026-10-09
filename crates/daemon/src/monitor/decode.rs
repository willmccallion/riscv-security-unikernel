#![cfg_attr(not(test), deny(clippy::indexing_slicing))]
//! Decoding captured frames into the fields the monitor analyses.
//!
//! Every function here is pure and bounds-checked: frames come straight
//! off the wire, so any of them may be truncated or crafted. A zero IPv4
//! total length, or a zero IPv6 payload length ahead of a jumbo option,
//! is read as "to the end of the frame": segmentation offload hands
//! capture sockets outgoing TCP super-packets that leave it unset.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// How frames on an interface or in a capture file begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// An Ethernet II header, possibly followed by VLAN tags.
    Ethernet,
    /// A bare IPv4 or IPv6 packet, as on tun and WireGuard interfaces.
    RawIp,
    /// Linux "cooked" capture (SLL), as `tcpdump -i any` records.
    LinuxSll,
    /// Linux cooked capture, version 2 (SLL2).
    LinuxSll2,
}

/// An IP packet's addresses and transport, borrowing its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    /// Source address.
    pub src: IpAddr,
    /// Destination address.
    pub dst: IpAddr,
    /// What the IP packet carries.
    pub transport: Transport<'a>,
}

/// The transport layer of a decoded packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport<'a> {
    /// A TCP segment.
    Tcp(TcpSegment<'a>),
    /// A UDP datagram.
    Udp(UdpDatagram<'a>),
    /// ICMP or ICMPv6.
    Icmp,
    /// A non-first IP fragment, which carries no transport header.
    Fragment,
    /// Any other protocol, by IP protocol number.
    Other(u8),
}

/// The TCP fields the monitor uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number of the first payload byte.
    pub sequence: u32,
    /// The flag bits.
    pub flags: TcpFlags,
    /// Data after the header, without link-layer padding.
    pub payload: &'a [u8],
}

/// The low eight TCP flag bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags(u8);

impl TcpFlags {
    const FIN: u8 = 0x01;
    const SYN: u8 = 0x02;
    const RST: u8 = 0x04;
    const ACK: u8 = 0x10;

    /// Flags from the header byte.
    pub const fn new(bits: u8) -> Self {
        Self(bits)
    }

    /// SYN without ACK: a client opening a connection.
    pub const fn is_connection_attempt(self) -> bool {
        self.0 & Self::SYN != 0 && self.0 & Self::ACK == 0
    }

    /// SYN with ACK: a server accepting a connection.
    pub const fn is_syn_ack(self) -> bool {
        self.0 & Self::SYN != 0 && self.0 & Self::ACK != 0
    }

    /// FIN or RST: one side is ending the connection.
    pub const fn is_close(self) -> bool {
        self.0 & (Self::FIN | Self::RST) != 0
    }
}

/// The UDP fields the monitor uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Data after the header, without link-layer padding.
    pub payload: &'a [u8],
}

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;
const ETHERNET_HEADER_LEN: usize = 14;
const SLL_HEADER_LEN: usize = 16;
const SLL_PROTOCOL_OFFSET: usize = 14;
const SLL2_HEADER_LEN: usize = 20;
const SLL2_PROTOCOL_OFFSET: usize = 0;
const VLAN_TAG_LEN: usize = 4;
const MAX_VLAN_TAGS: usize = 2;

const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;
const PROTO_ICMPV6: u8 = 58;

/// IPv6 extension headers this decoder steps over to reach the transport.
const IPV6_HOP_BY_HOP: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_AUTH: u8 = 51;
const IPV6_DEST_OPTIONS: u8 = 60;
/// Bounds the extension-header walk so a crafted chain cannot loop long.
const MAX_IPV6_EXTENSIONS: usize = 8;

/// Decodes a frame of the given link type; `None` if it is not an IP
/// packet or is too short to be one.
pub fn decode(link: LinkType, frame: &[u8]) -> Option<Packet<'_>> {
    match link {
        LinkType::Ethernet => decode_ethertype(read_u16(frame, 12)?, frame.get(ETHERNET_HEADER_LEN..)?),
        LinkType::RawIp => decode_ip(frame),
        LinkType::LinuxSll => decode_ethertype(read_u16(frame, SLL_PROTOCOL_OFFSET)?, frame.get(SLL_HEADER_LEN..)?),
        LinkType::LinuxSll2 => decode_ethertype(read_u16(frame, SLL2_PROTOCOL_OFFSET)?, frame.get(SLL2_HEADER_LEN..)?),
    }
}

/// Why a frame did not decode as an IP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NotIp {
    /// Too short to hold its link header.
    Truncated,
    /// A link-layer protocol other than IP, by EtherType; values below
    /// 0x0600 are 802.3 lengths, used by LLC protocols such as STP.
    EtherType(u16),
    /// Labelled IPv4 or IPv6, but malformed.
    MalformedIp,
    /// A frame on a bare-IP link whose first byte names no IP version.
    UnknownRaw(u8),
}

impl fmt::Display for NotIp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated"),
            Self::EtherType(0x0806) => f.write_str("ARP"),
            Self::EtherType(0x88CC) => f.write_str("LLDP"),
            Self::EtherType(0x888E) => f.write_str("EAPOL"),
            Self::EtherType(length) if *length < 0x0600 => f.write_str("802.3/LLC"),
            Self::EtherType(other) => write!(f, "EtherType {other:#06x}"),
            Self::MalformedIp => f.write_str("malformed IP"),
            Self::UnknownRaw(first) => write!(f, "bare frame starting {first:#04x}"),
        }
    }
}

/// Says why `frame`, which [`decode`] rejected, is not an IP packet.
pub fn classify_rejected(link: LinkType, frame: &[u8]) -> NotIp {
    let (ethertype, rest) = match link {
        LinkType::RawIp => {
            return match frame.first() {
                None => NotIp::Truncated,
                Some(&first) if first >> 4 == 4 || first >> 4 == 6 => NotIp::MalformedIp,
                Some(&first) => NotIp::UnknownRaw(first),
            };
        }
        LinkType::Ethernet => (read_u16(frame, 12), frame.get(ETHERNET_HEADER_LEN..)),
        LinkType::LinuxSll => (read_u16(frame, SLL_PROTOCOL_OFFSET), frame.get(SLL_HEADER_LEN..)),
        LinkType::LinuxSll2 => (read_u16(frame, SLL2_PROTOCOL_OFFSET), frame.get(SLL2_HEADER_LEN..)),
    };
    let (Some(mut ethertype), Some(mut rest)) = (ethertype, rest) else {
        return NotIp::Truncated;
    };
    for _ in 0..MAX_VLAN_TAGS {
        if ethertype != ETHERTYPE_VLAN && ethertype != ETHERTYPE_QINQ {
            break;
        }
        let (Some(inner), Some(after)) = (read_u16(rest, 2), rest.get(VLAN_TAG_LEN..)) else {
            return NotIp::Truncated;
        };
        ethertype = inner;
        rest = after;
    }
    match ethertype {
        ETHERTYPE_IPV4 | ETHERTYPE_IPV6 => NotIp::MalformedIp,
        other => NotIp::EtherType(other),
    }
}

/// Decodes what follows a link header that named `ethertype`, stepping
/// over VLAN tags.
fn decode_ethertype(mut ethertype: u16, mut rest: &[u8]) -> Option<Packet<'_>> {
    for _ in 0..MAX_VLAN_TAGS {
        if ethertype != ETHERTYPE_VLAN && ethertype != ETHERTYPE_QINQ {
            break;
        }
        ethertype = read_u16(rest, 2)?;
        rest = rest.get(VLAN_TAG_LEN..)?;
    }
    match ethertype {
        ETHERTYPE_IPV4 => decode_ipv4(rest),
        ETHERTYPE_IPV6 => decode_ipv6(rest),
        _ => None,
    }
}

fn decode_ip(packet: &[u8]) -> Option<Packet<'_>> {
    match packet.first()? >> 4 {
        4 => decode_ipv4(packet),
        6 => decode_ipv6(packet),
        _ => None,
    }
}

fn decode_ipv4(packet: &[u8]) -> Option<Packet<'_>> {
    let first = *packet.first()?;
    let header_len = usize::from(first & 0x0F) * 4;
    if first >> 4 != 4 || header_len < 20 {
        return None;
    }
    let total_len = usize::from(read_u16(packet, 2)?);
    let end = if total_len == 0 { packet.len() } else { total_len.min(packet.len()) };
    let packet = packet.get(..end)?;
    if packet.len() < header_len {
        return None;
    }
    let fragment_offset = read_u16(packet, 6)? & 0x1FFF;
    let src = Ipv4Addr::from(read_array::<4>(packet, 12)?);
    let dst = Ipv4Addr::from(read_array::<4>(packet, 16)?);
    let transport = if fragment_offset == 0 {
        decode_transport(*packet.get(9)?, packet.get(header_len..)?)
    } else {
        Transport::Fragment
    };
    Some(Packet {
        src: IpAddr::V4(src),
        dst: IpAddr::V4(dst),
        transport,
    })
}

fn decode_ipv6(packet: &[u8]) -> Option<Packet<'_>> {
    const HEADER_LEN: usize = 40;
    if packet.first()? >> 4 != 6 {
        return None;
    }
    let payload_len = usize::from(read_u16(packet, 4)?);
    let src = Ipv6Addr::from(read_array::<16>(packet, 8)?);
    let dst = Ipv6Addr::from(read_array::<16>(packet, 24)?);
    let jumbo = payload_len == 0 && packet.get(6) == Some(&IPV6_HOP_BY_HOP);
    let end = if jumbo { packet.len() } else { (HEADER_LEN + payload_len).min(packet.len()) };
    let payload = packet.get(HEADER_LEN..end)?;
    let next_header = *packet.get(6)?;
    let transport = ipv6_transport(next_header, payload).unwrap_or(Transport::Other(next_header));
    Some(Packet {
        src: IpAddr::V6(src),
        dst: IpAddr::V6(dst),
        transport,
    })
}

/// Follows the extension-header chain from `next_header` to the
/// transport; `None` if the chain is truncated or too long.
fn ipv6_transport(mut next_header: u8, mut rest: &[u8]) -> Option<Transport<'_>> {
    for _ in 0..MAX_IPV6_EXTENSIONS {
        let header_len = match next_header {
            IPV6_HOP_BY_HOP | IPV6_ROUTING | IPV6_DEST_OPTIONS => (usize::from(*rest.get(1)?) + 1) * 8,
            IPV6_AUTH => (usize::from(*rest.get(1)?) + 2) * 4,
            IPV6_FRAGMENT => {
                if read_u16(rest, 2)? & 0xFFF8 != 0 {
                    return Some(Transport::Fragment);
                }
                8
            }
            transport => return Some(decode_transport(transport, rest)),
        };
        next_header = *rest.first()?;
        rest = rest.get(header_len..)?;
    }
    None
}

fn decode_transport(protocol: u8, segment: &[u8]) -> Transport<'_> {
    let decoded = match protocol {
        PROTO_TCP => decode_tcp(segment).map(Transport::Tcp),
        PROTO_UDP => decode_udp(segment).map(Transport::Udp),
        PROTO_ICMP | PROTO_ICMPV6 => Some(Transport::Icmp),
        _ => None,
    };
    decoded.unwrap_or(Transport::Other(protocol))
}

fn decode_tcp(segment: &[u8]) -> Option<TcpSegment<'_>> {
    let header_len = usize::from(*segment.get(12)? >> 4) * 4;
    if header_len < 20 {
        return None;
    }
    Some(TcpSegment {
        src_port: read_u16(segment, 0)?,
        dst_port: read_u16(segment, 2)?,
        sequence: read_array::<4>(segment, 4).map(u32::from_be_bytes)?,
        flags: TcpFlags::new(*segment.get(13)?),
        payload: segment.get(header_len..)?,
    })
}

fn decode_udp(datagram: &[u8]) -> Option<UdpDatagram<'_>> {
    const HEADER_LEN: usize = 8;
    let length = usize::from(read_u16(datagram, 4)?);
    let end = if length >= HEADER_LEN { length.min(datagram.len()) } else { datagram.len() };
    Some(UdpDatagram {
        src_port: read_u16(datagram, 0)?,
        dst_port: read_u16(datagram, 2)?,
        payload: datagram.get(HEADER_LEN..end)?,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    read_array::<2>(bytes, offset).map(u16::from_be_bytes)
}

fn read_array<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..offset.checked_add(N)?)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn ipv4(protocol: u8, l4: &[u8]) -> Vec<u8> {
        let total = u16::try_from(20 + l4.len()).unwrap();
        let mut p = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, protocol, 0, 0, 10, 0, 0, 1, 93, 184, 216, 34];
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p.extend_from_slice(l4);
        p
    }

    fn ipv6(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        p.extend_from_slice(&[next_header, 64]);
        p.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&"2606:4700::1111".parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(payload);
        p
    }

    fn tcp(src_port: u16, dst_port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&src_port.to_be_bytes());
        t[2..4].copy_from_slice(&dst_port.to_be_bytes());
        t[4..8].copy_from_slice(&7u32.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = flags;
        t.extend_from_slice(payload);
        t
    }

    fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
        let mut u = vec![0u8; 8];
        u[0..2].copy_from_slice(&src_port.to_be_bytes());
        u[2..4].copy_from_slice(&dst_port.to_be_bytes());
        u[4..6].copy_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
        u.extend_from_slice(payload);
        u
    }

    #[test]
    fn decodes_tcp_over_ipv4_over_ethernet() {
        let frame = ethernet(ETHERTYPE_IPV4, &ipv4(PROTO_TCP, &tcp(51000, 443, 0x02, b"")));

        let packet = decode(LinkType::Ethernet, &frame).unwrap();

        assert_eq!(packet.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(packet.dst, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
        let Transport::Tcp(segment) = packet.transport else { panic!("not TCP") };
        assert_eq!((segment.src_port, segment.dst_port, segment.sequence), (51000, 443, 7));
        assert!(segment.flags.is_connection_attempt());
    }

    #[test]
    fn ethernet_padding_is_not_payload() {
        let mut frame = ethernet(ETHERTYPE_IPV4, &ipv4(PROTO_UDP, &udp(53, 40000, b"dns")));
        frame.extend_from_slice(&[0xEE; 12]);

        let packet = decode(LinkType::Ethernet, &frame).unwrap();

        let Transport::Udp(datagram) = packet.transport else { panic!("not UDP") };
        assert_eq!(datagram.payload, b"dns");
    }

    #[test]
    fn steps_over_stacked_vlan_tags() {
        let mut inner = vec![0x81, 0x00, 0x00, 0x0A, 0x08, 0x00];
        inner.extend_from_slice(&ipv4(PROTO_UDP, &udp(1, 2, b"")));
        let frame = ethernet(ETHERTYPE_QINQ, &[&[0x00, 0x14][..], &inner].concat());

        assert!(matches!(decode(LinkType::Ethernet, &frame).unwrap().transport, Transport::Udp(_)));
    }

    #[test]
    fn decodes_linux_cooked_captures() {
        let ip = ipv4(PROTO_UDP, &udp(53, 40000, b"x"));
        let mut sll = vec![0, 4, 0, 1, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0, 0x08, 0x00];
        sll.extend_from_slice(&ip);
        let mut sll2 = vec![0x08, 0x00, 0, 0, 0, 0, 0, 2, 0, 1, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0];
        sll2.extend_from_slice(&ip);

        assert!(matches!(decode(LinkType::LinuxSll, &sll).unwrap().transport, Transport::Udp(_)));
        assert!(matches!(decode(LinkType::LinuxSll2, &sll2).unwrap().transport, Transport::Udp(_)));
    }

    #[test]
    fn decodes_udp_over_ipv6_behind_extension_headers() {
        let mut chain = vec![IPV6_DEST_OPTIONS, 0, 0, 0, 0, 0, 0, 0];
        chain.extend_from_slice(&[PROTO_UDP, 0, 0, 0, 0, 0, 0, 0]);
        chain.extend_from_slice(&udp(443, 50000, b"quic"));

        let bytes = ipv6(IPV6_HOP_BY_HOP, &chain);

        let packet = decode(LinkType::RawIp, &bytes).unwrap();

        assert_eq!(packet.dst, IpAddr::V6("2606:4700::1111".parse().unwrap()));
        let Transport::Udp(datagram) = packet.transport else { panic!("not UDP") };
        assert_eq!((datagram.src_port, datagram.payload), (443, &b"quic"[..]));
    }

    #[test]
    fn offloaded_super_packets_with_no_length_are_still_decoded() {
        let mut v4 = ipv4(PROTO_TCP, &tcp(443, 50000, 0x10, &[7; 3000]));
        v4[2..4].copy_from_slice(&[0, 0]);

        let Transport::Tcp(segment) = decode(LinkType::RawIp, &v4).unwrap().transport else { panic!("not TCP") };

        assert_eq!(segment.payload.len(), 3000);
    }

    #[test]
    fn later_fragments_carry_no_transport() {
        let mut v4 = ipv4(PROTO_UDP, &[0; 16]);
        v4[6..8].copy_from_slice(&0x00B9u16.to_be_bytes());
        let v6 = ipv6(IPV6_FRAGMENT, &[PROTO_UDP, 0, 0x05, 0x00, 0, 0, 0, 1, 0, 0]);

        assert_eq!(decode(LinkType::RawIp, &v4).unwrap().transport, Transport::Fragment);
        assert_eq!(decode(LinkType::RawIp, &v6).unwrap().transport, Transport::Fragment);
    }

    #[test]
    fn non_ip_and_truncated_frames_are_rejected() {
        let arp = ethernet(0x0806, &[0; 28]);
        let truncated = ethernet(ETHERTYPE_IPV4, &[0x45, 0, 0]);

        assert_eq!(decode(LinkType::Ethernet, &arp), None);
        assert_eq!(decode(LinkType::Ethernet, &truncated), None);
        assert_eq!(decode(LinkType::RawIp, &[]), None);
    }

    #[test]
    fn rejected_frames_are_classified() {
        let arp = ethertype_frame(0x0806, &[0; 28]);
        let stp = ethertype_frame(0x0026, &[0; 38]);
        let bad_ip = ethertype_frame(ETHERTYPE_IPV4, &[0x45, 0, 0]);

        assert_eq!(classify_rejected(LinkType::Ethernet, &arp).to_string(), "ARP");
        assert_eq!(classify_rejected(LinkType::Ethernet, &stp).to_string(), "802.3/LLC");
        assert_eq!(classify_rejected(LinkType::Ethernet, &bad_ip), NotIp::MalformedIp);
        assert_eq!(classify_rejected(LinkType::Ethernet, &[0; 5]), NotIp::Truncated);
        assert_eq!(classify_rejected(LinkType::RawIp, &[0x00, 0x01]), NotIp::UnknownRaw(0));
        assert_eq!(classify_rejected(LinkType::RawIp, &[0x60]), NotIp::MalformedIp);
    }

    fn ethertype_frame(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        ethernet(ethertype, payload)
    }

    #[test]
    fn a_truncated_transport_header_is_reported_as_other() {
        let bytes = ipv4(PROTO_TCP, &[0; 10]);

        let packet = decode(LinkType::RawIp, &bytes).unwrap();

        assert_eq!(packet.transport, Transport::Other(PROTO_TCP));
    }

    #[test]
    fn decoding_never_panics_on_any_prefix_of_a_frame() {
        let frame = ethernet(ETHERTYPE_IPV6, &ipv6(PROTO_TCP, &tcp(1, 2, 0x18, b"hello")));

        for end in 0..=frame.len() {
            let _ = decode(LinkType::Ethernet, &frame[..end]);
        }
    }
}
