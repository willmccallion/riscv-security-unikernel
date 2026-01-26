//! Network protocol constants and packet layout definitions.
//!
//! This module provides strongly-typed constants for protocol numbers,
//! Ethernet types, packet offsets, and protocol-specific values used
//! throughout the network stack.

/// Internet Protocol (IP) protocol numbers.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    /// Internet Control Message Protocol.
    Icmp = 1,
    /// Transmission Control Protocol.
    Tcp = 6,
    /// User Datagram Protocol.
    Udp = 17,
}

impl IpProtocol {
    /// Converts a u8 protocol number to the enum variant.
    ///
    /// Returns None if the protocol number is not recognized.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Icmp),
            6 => Some(Self::Tcp),
            17 => Some(Self::Udp),
            _ => None,
        }
    }
}

/// Ethernet frame type identifiers.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthernetType {
    /// Address Resolution Protocol.
    Arp = 0x0806,
    /// Internet Protocol version 4.
    Ipv4 = 0x0800,
}

impl EthernetType {
    /// Converts a u16 Ethernet type to the enum variant.
    ///
    /// Returns None if the type is not recognized.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            0x0806 => Some(Self::Arp),
            0x0800 => Some(Self::Ipv4),
            _ => None,
        }
    }
}

/// ARP operation codes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpOpcode {
    /// ARP request.
    Request = 1,
    /// ARP reply.
    Reply = 2,
}

impl ArpOpcode {
    /// Converts a u16 opcode to the enum variant.
    pub fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Request),
            2 => Some(Self::Reply),
            _ => None,
        }
    }
}

/// ICMP message types.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    /// Echo reply (ping response).
    EchoReply = 0,
    /// Echo request (ping).
    EchoRequest = 8,
}

impl IcmpType {
    /// Converts a u8 ICMP type to the enum variant.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::EchoReply),
            8 => Some(Self::EchoRequest),
            _ => None,
        }
    }
}

/// Ethernet frame header offsets and sizes.
pub mod ethernet {
    /// Minimum Ethernet frame size in bytes.
    pub const MIN_FRAME_SIZE: usize = 14;
    /// Offset to Ethernet type field (bytes 12-13).
    pub const TYPE_OFFSET: usize = 12;
    /// Size of Ethernet type field in bytes.
    pub const TYPE_SIZE: usize = 2;
    /// Offset to source MAC address (bytes 6-11).
    pub const SRC_MAC_OFFSET: usize = 6;
    /// Size of MAC address in bytes.
    pub const MAC_ADDR_SIZE: usize = 6;
}

/// IPv4 header offsets and sizes.
pub mod ipv4 {
    /// Minimum IPv4 header size in bytes.
    pub const MIN_HEADER_SIZE: usize = 20;
    /// Offset to IP header within Ethernet frame.
    pub const HEADER_OFFSET: usize = 14;
    /// Offset to IP version and IHL field (byte 14).
    pub const VERSION_IHL_OFFSET: usize = 14;
    /// Offset to protocol field (byte 23).
    pub const PROTOCOL_OFFSET: usize = 23;
    /// Offset to source IP address (bytes 26-29).
    pub const SRC_IP_OFFSET: usize = 26;
    /// Offset to destination IP address (bytes 30-33).
    pub const DST_IP_OFFSET: usize = 30;
    /// Size of IP address in bytes.
    pub const IP_ADDR_SIZE: usize = 4;
    /// Mask for extracting IHL (Internet Header Length) from version/IHL byte.
    pub const IHL_MASK: u8 = 0x0F;
    /// IP version 4 identifier.
    pub const VERSION: u8 = 0x45;
    /// Default TTL value.
    pub const DEFAULT_TTL: u8 = 0x40;
}

/// ARP packet offsets and sizes.
pub mod arp {
    /// Minimum ARP packet size in bytes.
    pub const MIN_PACKET_SIZE: usize = 42;
    /// Offset to hardware type field (bytes 20-21).
    pub const HW_TYPE_OFFSET: usize = 20;
    /// Offset to operation code field (byte 21).
    pub const OPCODE_OFFSET: usize = 21;
    /// Offset to sender MAC address (bytes 22-27).
    pub const SENDER_MAC_OFFSET: usize = 22;
    /// Offset to sender IP address (bytes 28-31).
    pub const SENDER_IP_OFFSET: usize = 28;
    /// Offset to target MAC address (bytes 32-37).
    pub const TARGET_MAC_OFFSET: usize = 32;
    /// Offset to target IP address (bytes 38-41).
    pub const TARGET_IP_OFFSET: usize = 38;
}

/// TCP header offsets and sizes.
pub mod tcp {
    /// Minimum TCP header size in bytes.
    pub const MIN_HEADER_SIZE: usize = 20;
    /// Offset to TCP flags field within TCP header (byte 13).
    pub const FLAGS_OFFSET: usize = 13;
    /// Offset to source port (bytes 0-1).
    pub const SRC_PORT_OFFSET: usize = 0;
    /// Offset to destination port (bytes 2-3).
    pub const DST_PORT_OFFSET: usize = 2;
    /// Size of port number in bytes.
    pub const PORT_SIZE: usize = 2;
}

/// UDP header offsets and sizes.
pub mod udp {
    /// UDP header size in bytes.
    pub const HEADER_SIZE: usize = 8;
}

/// Broadcast MAC address (all ones).
pub const BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

/// Magic cookie value used in SYN cookie generation.
///
/// This constant is combined with source IP and port to create
/// stateless SYN cookies for SYN flood protection.
pub const SYN_COOKIE_MAGIC: u32 = 0xCAFEBABE;

/// Maximum safe packet length for ICMP echo reply processing.
///
/// Used to cap packet length when generating ICMP responses to
/// prevent buffer overflows and excessive processing.
pub const MAX_ICMP_REPLY_LEN: usize = 128;
