//! Network protocol constants and packet layout definitions.
//!
//! This module provides strongly-typed constants for protocol numbers,
//! Ethernet types, packet offsets, and protocol-specific values used
//! throughout the network stack.

wire_enum! {
    /// Internet Protocol (IP) protocol numbers.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum IpProtocol {
        /// Internet Control Message Protocol.
        Icmp = 1,
        /// Transmission Control Protocol.
        Tcp = 6,
        /// User Datagram Protocol.
        Udp = 17,
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
    pub const fn from_u16(value: u16) -> Option<Self> {
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
    pub const fn from_u16(value: u16) -> Option<Self> {
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
    pub const fn from_u8(value: u8) -> Option<Self> {
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
    /// Offset to the total length field (bytes 16-17).
    pub const TOTAL_LENGTH_OFFSET: usize = 16;
    /// Bits of the flags and fragment offset field set on any fragment: More
    /// Fragments and the 13-bit fragment offset. Don't Fragment alone does
    /// not make a fragment.
    pub const FRAGMENT_MASK: u16 = 0x3FFF;
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

    /// Field offsets within the IPv4 header.
    pub mod field {
        /// The version (high nibble) and header length in words (low).
        pub const VERSION_IHL: usize = 0;
        /// The two-byte total length of the datagram.
        pub const TOTAL_LEN: usize = 2;
        /// The two-byte flags and fragment offset.
        pub const FLAGS_FRAGMENT: usize = 6;
        /// Time to live.
        pub const TTL: usize = 8;
        /// The transport protocol number.
        pub const PROTOCOL: usize = 9;
        /// The two-byte header checksum.
        pub const CHECKSUM: usize = 10;
        /// The source address.
        pub const SRC: usize = 12;
        /// The destination address.
        pub const DST: usize = 16;
    }
}

/// ARP packet offsets and sizes.
pub mod arp {
    /// Minimum ARP packet size in bytes.
    pub const MIN_PACKET_SIZE: usize = 42;
    /// Offset to the hardware type field (bytes 14-15, right after the
    /// Ethernet header).
    pub const HW_TYPE_OFFSET: usize = 14;
    /// The hardware type of Ethernet ARP; anything else is not ours to
    /// answer.
    pub const HW_TYPE_ETHERNET: u16 = 1;
    /// Offset to operation code field (bytes 20-21). Two bytes wide;
    /// Request = 0x0001, Reply = 0x0002.
    pub const OPCODE_OFFSET: usize = 20;
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
    /// Offset to the byte whose high four bits give the header length in
    /// 32-bit words.
    pub const DATA_OFFSET_OFFSET: usize = 12;
    /// Offset to TCP flags field within TCP header (byte 13).
    pub const FLAGS_OFFSET: usize = 13;
    /// Offset of the four-byte sequence number.
    pub const SEQ_OFFSET: usize = 4;
    /// Offset of the four-byte acknowledgment number.
    pub const ACK_OFFSET: usize = 8;
    /// Offset of the two-byte receive window.
    pub const WINDOW_OFFSET: usize = 14;
    /// Offset of the two-byte checksum.
    pub const CHECKSUM_OFFSET: usize = 16;
    /// Offset of the two-byte urgent pointer.
    pub const URGENT_OFFSET: usize = 18;
    /// Offset to source port (bytes 0-1).
    pub const SRC_PORT_OFFSET: usize = 0;
    /// Offset to destination port (bytes 2-3).
    pub const DST_PORT_OFFSET: usize = 2;
}

/// ICMP header sizes.
pub mod icmp {
    /// Type, code, checksum and the four bytes every message type defines.
    pub const HEADER_SIZE: usize = 8;
    /// Offset of the two-byte checksum.
    pub const CHECKSUM_OFFSET: usize = 2;
}

/// UDP header offsets and sizes.
pub mod udp {
    /// UDP header size in bytes.
    pub const HEADER_SIZE: usize = 8;
    /// Offset of the length field within the UDP header.
    pub const LENGTH_OFFSET: usize = 4;
}

/// Broadcast MAC address (all ones).
pub const BROADCAST_MAC: [u8; 6] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
