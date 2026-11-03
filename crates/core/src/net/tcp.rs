//! TCP header flags and port extraction.

use crate::net::constants::tcp as tcp_consts;

/// TCP FIN flag bit.
pub const TCP_FIN: u16 = 0x0001;

/// TCP SYN flag bit.
pub const TCP_SYN: u16 = 0x0002;

/// TCP RST flag bit.
pub const TCP_RST: u16 = 0x0004;

/// TCP ACK flag bit.
pub const TCP_ACK: u16 = 0x0010;

/// Whether a segment with these flags opens a connection: SYN without ACK,
/// FIN or RST.
pub const fn is_connection_request(flags: u16) -> bool {
    flags & (TCP_SYN | TCP_ACK | TCP_FIN | TCP_RST) == TCP_SYN
}

/// Reads the source and destination ports (host byte order) from the start
/// of a TCP or UDP header, or `None` if `data` is too short.
pub const fn extract_ports(data: &[u8]) -> Option<(u16, u16)> {
    if data.len() < tcp_consts::DST_PORT_OFFSET + tcp_consts::PORT_SIZE {
        return None;
    }
    let src_port = u16::from_be_bytes([
        data[tcp_consts::SRC_PORT_OFFSET],
        data[tcp_consts::SRC_PORT_OFFSET + 1],
    ]);
    let dst_port = u16::from_be_bytes([
        data[tcp_consts::DST_PORT_OFFSET],
        data[tcp_consts::DST_PORT_OFFSET + 1],
    ]);
    Some((src_port, dst_port))
}
