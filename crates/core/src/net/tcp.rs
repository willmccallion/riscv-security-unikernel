//! TCP header flags and port extraction.

use crate::net::constants::tcp as tcp_consts;
use core::ops::BitOr;

/// The flag byte of a TCP header: CWR, ECE, URG, ACK, PSH, RST, SYN, FIN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlags(u8);

impl TcpFlags {
    /// No more data from the sender.
    pub const FIN: Self = Self(0x01);
    /// Synchronise sequence numbers: open a connection.
    pub const SYN: Self = Self(0x02);
    /// Reset the connection.
    pub const RST: Self = Self(0x04);
    /// Push buffered data to the application.
    pub const PSH: Self = Self(0x08);
    /// The acknowledgment number is valid.
    pub const ACK: Self = Self(0x10);
    /// The urgent pointer is valid.
    pub const URG: Self = Self(0x20);
    /// A server's answer to a connection request.
    pub const SYN_ACK: Self = Self(Self::SYN.0 | Self::ACK.0);

    /// Flags from the header byte.
    pub const fn new(bits: u8) -> Self {
        Self(bits)
    }

    /// The header byte.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// Whether every flag of `flags` is set.
    pub const fn contains(self, flags: Self) -> bool {
        self.0 & flags.0 == flags.0
    }

    /// Whether any flag of `flags` is set.
    const fn intersects(self, flags: Self) -> bool {
        self.0 & flags.0 != 0
    }

    /// SYN without ACK, FIN or RST: a clean request to open a connection,
    /// the only segment the stack answers with a SYN cookie.
    pub const fn is_connection_request(self) -> bool {
        let opening = Self(Self::SYN.0 | Self::ACK.0 | Self::FIN.0 | Self::RST.0);
        self.0 & opening.0 == Self::SYN.0
    }

    /// SYN without ACK: a client trying to open a connection.
    pub const fn is_connection_attempt(self) -> bool {
        self.contains(Self::SYN) && !self.contains(Self::ACK)
    }

    /// SYN with ACK: a server accepting a connection.
    pub const fn is_syn_ack(self) -> bool {
        self.contains(Self::SYN_ACK)
    }

    /// FIN or RST: one side is ending the connection.
    pub const fn is_close(self) -> bool {
        self.intersects(Self(Self::FIN.0 | Self::RST.0))
    }

    /// FIN, PSH and URG together, the Xmas-tree probe that slips past
    /// simple firewalls.
    pub const fn is_xmas(self) -> bool {
        self.contains(Self(Self::FIN.0 | Self::PSH.0 | Self::URG.0))
    }

    /// No flag at all, the null probe used for OS fingerprinting.
    pub const fn is_null(self) -> bool {
        self.0 == 0
    }
}

impl BitOr for TcpFlags {
    type Output = Self;

    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_syn_with_fin_is_a_connection_attempt_but_not_a_clean_request() {
        let syn_fin = TcpFlags::SYN | TcpFlags::FIN;

        assert!(syn_fin.is_connection_attempt());
        assert!(!syn_fin.is_connection_request());
        assert!(TcpFlags::SYN.is_connection_request());
    }

    #[test]
    fn an_xmas_probe_needs_fin_psh_and_urg_together() {
        let xmas = TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG;

        assert!(xmas.is_xmas());
        assert!((xmas | TcpFlags::ACK).is_xmas());
        assert!(!(TcpFlags::FIN | TcpFlags::PSH).is_xmas());
    }

    #[test]
    fn only_a_segment_without_any_flag_is_null() {
        assert!(TcpFlags::new(0).is_null());
        assert!(!TcpFlags::new(0x40).is_null());
    }
}
