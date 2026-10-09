//! Network protocol stack implementation.
//!
//! This module provides network protocol processing including Ethernet,
//! IPv4, ARP, ICMP, and TCP handling. It processes incoming packets
//! and extracts payload data for security inspection.

/// Network protocol constants and packet layout definitions.
pub mod constants;
/// Network protocol stack for packet processing and protocol handling.
pub mod stack;
/// TCP header flags and port extraction.
pub mod tcp;

/// Egress side for frames emitted by the network stack.
///
/// Implemented by the kernel over the VirtIO NIC and (in future) by
/// the Linux daemon over `AF_XDP` TX rings or `nfnetlink` verdicts. The
/// stack only calls [`PacketSink::send`] when it needs to emit an ARP
/// reply, an ICMP echo reply, or a TCP SYN-ACK; otherwise it just
/// returns the payload slice to the caller for inspection.
pub trait PacketSink {
    /// Transmits a fully-formed Ethernet frame.
    fn send(&mut self, frame: &[u8]);
}
