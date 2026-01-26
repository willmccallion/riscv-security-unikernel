//! TCP (Transmission Control Protocol) header definitions.
//!
//! Provides structures and constants for working with TCP headers,
//! including flag definitions and header construction utilities.

use crate::net::constants::tcp as tcp_consts;

/// TCP header structure matching the standard TCP header format.
///
/// Fields are stored in network byte order (big-endian) as they appear
/// on the wire. The structure is packed to ensure correct memory layout.
#[repr(C, packed)]
pub struct TcpHeader {
    /// Source port in network byte order.
    pub src_port: u16,
    /// Destination port in network byte order.
    pub dst_port: u16,
    /// Sequence number in network byte order.
    pub seq_num: u32,
    /// Acknowledgment number in network byte order.
    pub ack_num: u32,
    /// Data offset (4 bits), reserved (6 bits), and flags (6 bits).
    pub data_offset_flags: u16,
    /// Window size in network byte order.
    pub window_size: u16,
    /// Checksum in network byte order.
    pub checksum: u16,
    /// Urgent pointer in network byte order.
    pub urgent_ptr: u16,
}

/// TCP SYN flag bit.
pub const TCP_SYN: u16 = 0x0002;

/// TCP ACK flag bit.
pub const TCP_ACK: u16 = 0x0010;

impl TcpHeader {
    /// Creates a new TCP header with the specified values.
    ///
    /// All values are converted to network byte order. The data offset
    /// is set to 5 (20 bytes) and the checksum is initialized to zero
    /// (must be calculated separately).
    ///
    /// # Arguments
    ///
    /// * `src` - Source port in host byte order
    /// * `dst` - Destination port in host byte order
    /// * `seq` - Sequence number in host byte order
    /// * `ack` - Acknowledgment number in host byte order
    /// * `flags` - TCP flags in host byte order
    pub fn new(src: u16, dst: u16, seq: u32, ack: u32, flags: u16) -> Self {
        let offset_flags = (5 << 12) | flags;
        Self {
            src_port: src.to_be(),
            dst_port: dst.to_be(),
            seq_num: seq.to_be(),
            ack_num: ack.to_be(),
            data_offset_flags: offset_flags.to_be(),
            window_size: 64240u16.to_be(),
            checksum: 0,
            urgent_ptr: 0,
        }
    }

    /// Extracts source and destination ports from a raw TCP header.
    ///
    /// Validates that the buffer contains at least a minimum TCP header
    /// before extracting port numbers. Uses the standard TCP header layout
    /// constants for offset calculations. This utility function is used
    /// when parsing TCP headers from packet payloads without constructing
    /// a full TcpHeader struct.
    ///
    /// # Arguments
    ///
    /// * `data` - Buffer containing TCP header starting at offset 0
    ///
    /// # Returns
    ///
    /// Some tuple of (src_port, dst_port) in host byte order if the header
    /// is valid, None otherwise
    pub fn extract_ports(data: &[u8]) -> Option<(u16, u16)> {
        if data.len() < tcp_consts::MIN_HEADER_SIZE {
            return None;
        }
        if data.len() < tcp_consts::DST_PORT_OFFSET + tcp_consts::PORT_SIZE {
            return None;
        }
        let src_port = ((data[tcp_consts::SRC_PORT_OFFSET] as u16) << 8)
            | (data[tcp_consts::SRC_PORT_OFFSET + 1] as u16);
        let dst_port = ((data[tcp_consts::DST_PORT_OFFSET] as u16) << 8)
            | (data[tcp_consts::DST_PORT_OFFSET + 1] as u16);
        Some((u16::from_be(src_port), u16::from_be(dst_port)))
    }
}
