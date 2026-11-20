//! Parsing a received frame once, into the fields later stages read.
//!
//! No stage re-checks a length or re-reads a header byte. An IPv4 datagram is accepted only if every header it carries fits inside
//! its total length, and that length inside the frame; bytes past it are
//! Ethernet padding and never read.

use core::net::Ipv4Addr;

use crate::net::constants::{EthernetType, IpProtocol, ethernet, icmp, ipv4, tcp, udp};
use crate::net::tcp::TcpFlags;

/// A received frame, by what it carries.
#[derive(Debug)]
pub enum Frame<'a> {
    /// An IPv4 datagram whose headers all fit inside it.
    Ipv4(Ipv4Packet<'a>),
    /// An ARP packet, not yet checked.
    Arp(&'a mut [u8]),
    /// Anything else, including an IPv4 frame too short for a header.
    Other(&'a [u8]),
}

impl Frame<'_> {
    /// The whole frame.
    pub const fn bytes(&self) -> &[u8] {
        match self {
            Self::Ipv4(packet) => packet.frame,
            Self::Arp(frame) => frame,
            Self::Other(frame) => frame,
        }
    }
}

/// An IPv4 datagram the pipeline drops without inspecting, with the header
/// fields its alert reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejected {
    /// Source address.
    pub src: Ipv4Addr,
    /// Destination address.
    pub dst: Ipv4Addr,
    /// The protocol number.
    pub protocol: u8,
    /// Why it was dropped.
    pub reason: Rejection,
}

/// Why an IPv4 datagram cannot be inspected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// A header is inconsistent or does not fit inside the datagram.
    Malformed,
    /// A fragment, which this host does not reassemble.
    Fragment,
}

/// Source and destination ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ports {
    /// Source port.
    pub src: u16,
    /// Destination port.
    pub dst: u16,
}

/// The TCP header fields the pipeline acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader {
    /// Source and destination ports.
    pub ports: Ports,
    /// Sequence number.
    pub seq: u32,
    /// The flag bits.
    pub flags: TcpFlags,
}

/// The transport layer of an IPv4 datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// A TCP segment.
    Tcp(TcpHeader),
    /// A UDP datagram.
    Udp(Ports),
    /// An ICMP message of this type.
    Icmp {
        /// The ICMP type byte.
        message_type: u8,
    },
    /// Any other protocol, by number.
    Other(u8),
}

impl Transport {
    /// The IP protocol number.
    pub const fn protocol(self) -> u8 {
        match self {
            Self::Tcp(_) => IpProtocol::Tcp as u8,
            Self::Udp(_) => IpProtocol::Udp as u8,
            Self::Icmp { .. } => IpProtocol::Icmp as u8,
            Self::Other(protocol) => protocol,
        }
    }

    /// The ports, for TCP and UDP only.
    pub const fn ports(self) -> Option<Ports> {
        match self {
            Self::Tcp(tcp) => Some(tcp.ports),
            Self::Udp(ports) => Some(ports),
            Self::Icmp { .. } | Self::Other(_) => None,
        }
    }
}

/// A checked IPv4 datagram, holding the frame it was parsed from so its
/// offsets can only ever index that frame.
#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    pub(super) frame: &'a mut [u8],
    /// Source address.
    pub src: Ipv4Addr,
    /// Destination address.
    pub dst: Ipv4Addr,
    /// What the datagram carries.
    pub transport: Transport,
    /// Frame offsets of the transport header and of the payload after it.
    pub(super) layout: Layout,
}

/// Where an IPv4 datagram's parts sit in its frame; every offset is at most
/// `end`, which is at most the frame's length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Layout {
    pub(super) transport: usize,
    pub(super) payload: usize,
    pub(super) payload_end: usize,
    pub(super) end: usize,
}

impl<'a> Ipv4Packet<'a> {
    /// The whole frame.
    pub const fn bytes(&self) -> &[u8] {
        self.frame
    }

    /// The bytes after the transport header: for UDP up to its length, for
    /// TCP up to the end of the datagram, and for ICMP and other protocols
    /// the whole transport section.
    pub fn payload(&self) -> &[u8] {
        &self.frame[self.layout.payload..self.layout.payload_end]
    }

    /// Gives up the packet for its payload.
    pub(super) fn into_payload(self) -> &'a [u8] {
        let frame: &'a [u8] = self.frame;
        &frame[self.layout.payload..self.layout.payload_end]
    }
}

/// Parses `frame`.
///
/// # Errors
///
/// [`Rejected`] for an IPv4 datagram with a bad version, header length or
/// total length, a transport header that does not fit, or a fragment.
pub fn parse(frame: &mut [u8]) -> Result<Frame<'_>, Rejected> {
    match ethertype(frame) {
        Some(EthernetType::Arp) => Ok(Frame::Arp(frame)),
        Some(EthernetType::Ipv4) => parse_ipv4(frame),
        None => Ok(Frame::Other(frame)),
    }
}

fn ethertype(frame: &[u8]) -> Option<EthernetType> {
    let bytes = frame.get(ethernet::TYPE_OFFSET..ethernet::TYPE_OFFSET + ethernet::TYPE_SIZE)?;
    EthernetType::from_u16(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn parse_ipv4(frame: &mut [u8]) -> Result<Frame<'_>, Rejected> {
    let Some(header) = frame[ipv4::HEADER_OFFSET..].first_chunk::<{ ipv4::MIN_HEADER_SIZE }>()
    else {
        return Ok(Frame::Other(frame));
    };
    let src = address_at(header, ipv4::field::SRC);
    let dst = address_at(header, ipv4::field::DST);
    let protocol = header[ipv4::field::PROTOCOL];
    let reject = |reason| Rejected {
        src,
        dst,
        protocol,
        reason,
    };
    let (transport_start, end) =
        datagram_bounds(header, frame.len()).ok_or_else(|| reject(Rejection::Malformed))?;
    if u16_at(header, ipv4::field::FLAGS_FRAGMENT) & ipv4::FRAGMENT_MASK != 0 {
        return Err(reject(Rejection::Fragment));
    }
    let (transport, payload, payload_end) = parse_transport(protocol, &frame[transport_start..end])
        .ok_or_else(|| reject(Rejection::Malformed))?;
    Ok(Frame::Ipv4(Ipv4Packet {
        frame,
        src,
        dst,
        transport,
        layout: Layout {
            transport: transport_start,
            payload: transport_start + payload,
            payload_end: transport_start + payload_end,
            end,
        },
    }))
}

/// Frame offsets of the transport header and the datagram's end, if the
/// version is 4, the header is at least the minimum, and the total length
/// covers the header and fits in a frame of `frame_len` bytes.
fn datagram_bounds(
    header: &[u8; ipv4::MIN_HEADER_SIZE],
    frame_len: usize,
) -> Option<(usize, usize)> {
    const MIN_IHL_WORDS: u8 = 5;
    let version_ihl = header[ipv4::field::VERSION_IHL];
    let ihl_words = version_ihl & ipv4::IHL_MASK;
    let header_len = usize::from(ihl_words) * 4;
    let total_len = usize::from(u16_at(header, ipv4::field::TOTAL_LEN));
    let end = ipv4::HEADER_OFFSET + total_len;
    let is_valid = version_ihl >> 4 == 4
        && ihl_words >= MIN_IHL_WORDS
        && total_len >= header_len
        && end <= frame_len;
    is_valid.then_some((ipv4::HEADER_OFFSET + header_len, end))
}

/// The transport carried in `section`, the datagram after its IPv4 header,
/// with its payload's start and end within `section`; `None` if the
/// transport header does not fit or is inconsistent.
fn parse_transport(protocol: u8, section: &[u8]) -> Option<(Transport, usize, usize)> {
    match IpProtocol::from_u8(protocol) {
        Some(IpProtocol::Tcp) => parse_tcp(section),
        Some(IpProtocol::Udp) => parse_udp(section),
        Some(IpProtocol::Icmp) => {
            let message_type = *section.get(..icmp::HEADER_SIZE)?.first()?;
            Some((Transport::Icmp { message_type }, 0, section.len()))
        }
        None => Some((Transport::Other(protocol), 0, section.len())),
    }
}

fn parse_tcp(section: &[u8]) -> Option<(Transport, usize, usize)> {
    let header = section.get(..tcp::MIN_HEADER_SIZE)?;
    let header_len = usize::from(header[tcp::DATA_OFFSET_OFFSET] >> 4) * 4;
    if header_len < tcp::MIN_HEADER_SIZE || header_len > section.len() {
        return None;
    }
    let segment = TcpHeader {
        ports: ports(header),
        seq: u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
        flags: TcpFlags::new(header[tcp::FLAGS_OFFSET]),
    };
    Some((Transport::Tcp(segment), header_len, section.len()))
}

fn parse_udp(section: &[u8]) -> Option<(Transport, usize, usize)> {
    let header = section.get(..udp::HEADER_SIZE)?;
    let udp_len = usize::from(u16_at(header, udp::LENGTH_OFFSET));
    if udp_len < udp::HEADER_SIZE || udp_len > section.len() {
        return None;
    }
    Some((Transport::Udp(ports(header)), udp::HEADER_SIZE, udp_len))
}

/// The ports at the start of a TCP or UDP header of at least four bytes.
const fn ports(header: &[u8]) -> Ports {
    Ports {
        src: u16_at(header, tcp::SRC_PORT_OFFSET),
        dst: u16_at(header, tcp::DST_PORT_OFFSET),
    }
}

const fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

const fn address_at(bytes: &[u8], offset: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    )
}
