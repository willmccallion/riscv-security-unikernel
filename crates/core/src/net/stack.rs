//! Network protocol stack for packet processing.
//!
//! Handles Ethernet, IPv4, ARP, ICMP, and TCP protocols. Processes
//! incoming packets, generates responses where appropriate, and
//! extracts payload data for security inspection.

use crate::config::{IP_ADDR, MAC_ADDR};
use crate::net::PacketSink;
use crate::net::constants::MAX_ICMP_REPLY_LEN;
use crate::net::constants::{
    ArpOpcode, EthernetType, IcmpType, IpProtocol, arp, ethernet, ipv4, tcp,
};
use crate::net::tcp::{TCP_ACK, TCP_SYN, TcpHeader};
use crate::security::hash::siphash24;

/// Per-boot secret keying the SYN-cookie PRF.
///
/// The kernel constructs one of these once at init time from the
/// `mcycle` CSR XORed with the MAC address; the daemon will eventually
/// derive its own from `getrandom`. Distinct secrets per reboot mean an
/// attacker cannot reuse a cookie value seen before a restart, and a
/// secret-keyed cookie cannot be derived from packet headers and a
/// known compile-time constant the way the old `+ SYN_COOKIE_MAGIC`
/// formula could.
#[derive(Debug)]
pub struct SynCookieSecret([u8; 16]);

impl SynCookieSecret {
    /// Wraps 16 bytes of entropy into a secret. The caller is
    /// responsible for ensuring the bytes vary across reboots.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Computes the 32-bit SYN-cookie sequence number for the given
    /// 5-tuple. Uses SipHash-2-4 keyed by `self.0`, so the cookie is
    /// unforgeable to anyone who does not hold the secret.
    pub fn cookie(&self, src_ip: &[u8; 4], dst_ip: &[u8; 4], src_port: u16, dst_port: u16) -> u32 {
        let mut buf = [0u8; 12];
        buf[..4].copy_from_slice(src_ip);
        buf[4..8].copy_from_slice(dst_ip);
        buf[8..10].copy_from_slice(&src_port.to_be_bytes());
        buf[10..12].copy_from_slice(&dst_port.to_be_bytes());
        siphash24(&self.0, &buf) as u32
    }
}

/// Processes an incoming network packet.
///
/// Handles various protocol types:
/// - ARP: Generates ARP replies for address resolution
/// - ICMP: Responds to ping requests
/// - TCP SYN: Handles with SYN cookies (no payload returned)
/// - TCP data: Returns the TCP application payload for inspection
/// - Other IPv4: Extracts payload for security inspection
///
/// The packet buffer may be modified in-place for generating responses.
/// Replies are sent via `sink` — the caller supplies a concrete
/// [`PacketSink`] implementation tied to its underlying NIC or AF_XDP
/// TX ring.
///
/// # Arguments
///
/// * `packet` - Mutable reference to the packet buffer
/// * `sink`   - Egress for generated replies (ARP, ICMP echo, SYN-ACK)
///
/// # Returns
///
/// `Some` payload slice if available, `None` if the packet was consumed
/// (e.g., ARP reply sent) or invalid.
pub fn process_packet<'a, S: PacketSink>(
    packet: &'a mut [u8],
    sink: &mut S,
    syn_secret: &SynCookieSecret,
) -> Option<&'a [u8]> {
    if packet.len() < ethernet::MIN_FRAME_SIZE {
        return None;
    }
    if packet.len() < ethernet::TYPE_OFFSET + ethernet::TYPE_SIZE {
        return None;
    }
    let eth_type =
        (packet[ethernet::TYPE_OFFSET] as u16) << 8 | packet[ethernet::TYPE_OFFSET + 1] as u16;
    match EthernetType::from_u16(eth_type) {
        Some(EthernetType::Arp) => {
            handle_arp(packet, sink);
            None
        }
        Some(EthernetType::Ipv4) => handle_ipv4(packet, sink, syn_secret),
        _ => None,
    }
}

/// Handles ARP (Address Resolution Protocol) packets.
///
/// Responds to ARP requests for the kernel's IP address by generating
/// an ARP reply. The reply is constructed in-place by modifying the
/// original packet buffer and then sending it.
///
/// # Arguments
///
/// * `packet` - ARP packet buffer to process and modify
fn handle_arp<S: PacketSink>(packet: &mut [u8], sink: &mut S) {
    if packet.len() < arp::MIN_PACKET_SIZE {
        return;
    }
    // hw_type and opcode are both 2-byte big-endian fields. The
    // previous code read only the high byte of each, which works for
    // Ethernet ARP (hw_type=0x0001 has high byte 0x00) but lets a
    // non-Ethernet ARP (hw_type=0xFFFF, etc.) through because the
    // mask happened to alias to opcode bits. Audit MED-1.
    let hw_type = u16::from_be_bytes([
        packet[arp::HW_TYPE_OFFSET],
        packet[arp::HW_TYPE_OFFSET + 1],
    ]);
    let opcode = u16::from_be_bytes([
        packet[arp::OPCODE_OFFSET],
        packet[arp::OPCODE_OFFSET + 1],
    ]);
    if hw_type != 1 || ArpOpcode::from_u16(opcode) != Some(ArpOpcode::Request) {
        return;
    }
    if packet[arp::TARGET_IP_OFFSET..arp::TARGET_IP_OFFSET + ipv4::IP_ADDR_SIZE] != IP_ADDR {
        return;
    }

    let old_src_mac = [
        packet[ethernet::SRC_MAC_OFFSET],
        packet[ethernet::SRC_MAC_OFFSET + 1],
        packet[ethernet::SRC_MAC_OFFSET + 2],
        packet[ethernet::SRC_MAC_OFFSET + 3],
        packet[ethernet::SRC_MAC_OFFSET + 4],
        packet[ethernet::SRC_MAC_OFFSET + 5],
    ];
    packet[0..ethernet::MAC_ADDR_SIZE].copy_from_slice(&old_src_mac);
    packet[ethernet::SRC_MAC_OFFSET..ethernet::SRC_MAC_OFFSET + ethernet::MAC_ADDR_SIZE]
        .copy_from_slice(&MAC_ADDR);

    // Opcode is big-endian 2 bytes; Reply = 0x0002.
    packet[arp::OPCODE_OFFSET] = 0;
    packet[arp::OPCODE_OFFSET + 1] = ArpOpcode::Reply as u8;

    let old_sender_ip = [
        packet[arp::SENDER_IP_OFFSET],
        packet[arp::SENDER_IP_OFFSET + 1],
        packet[arp::SENDER_IP_OFFSET + 2],
        packet[arp::SENDER_IP_OFFSET + 3],
    ];

    packet[arp::TARGET_MAC_OFFSET..arp::TARGET_MAC_OFFSET + ethernet::MAC_ADDR_SIZE]
        .copy_from_slice(&old_src_mac);
    packet[arp::TARGET_IP_OFFSET..arp::TARGET_IP_OFFSET + ipv4::IP_ADDR_SIZE]
        .copy_from_slice(&old_sender_ip);

    packet[arp::SENDER_MAC_OFFSET..arp::SENDER_MAC_OFFSET + ethernet::MAC_ADDR_SIZE]
        .copy_from_slice(&MAC_ADDR);
    packet[arp::SENDER_IP_OFFSET..arp::SENDER_IP_OFFSET + ipv4::IP_ADDR_SIZE]
        .copy_from_slice(&IP_ADDR);

    sink.send(&packet[0..arp::MIN_PACKET_SIZE]);
}

/// Handles IPv4 packets.
///
/// Processes ICMP echo requests (ping) and TCP SYN packets, generating
/// appropriate responses. For other protocols, extracts and returns
/// the payload for security inspection.
///
/// # Arguments
///
/// * `packet` - IPv4 packet buffer to process
///
/// # Returns
///
/// Some payload slice if available, None if packet was consumed
fn handle_ipv4<'a, S: PacketSink>(
    packet: &'a mut [u8],
    sink: &mut S,
    syn_secret: &SynCookieSecret,
) -> Option<&'a [u8]> {
    if packet.len() < ipv4::HEADER_OFFSET + ipv4::MIN_HEADER_SIZE {
        return None;
    }
    let ihl = (packet[ipv4::VERSION_IHL_OFFSET] & ipv4::IHL_MASK) * 4;
    let protocol = packet[ipv4::PROTOCOL_OFFSET];

    if packet[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE] != IP_ADDR {
        return None;
    }

    if IpProtocol::from_u8(protocol) == Some(IpProtocol::Icmp) {
        let offset = ipv4::HEADER_OFFSET + ihl as usize;
        // Need at least 4 bytes (type + code + 2-byte checksum) to write
        // the echo reply header back into the buffer. RFC 792 actually
        // requires 8 (type/code/csum/id/seq), but only the first four
        // are written, so 4 is the OOB bound. Found by fuzzer crash 2.
        const ICMP_HEADER_MIN: usize = 4;
        if offset + ICMP_HEADER_MIN <= packet.len()
            && IcmpType::from_u8(packet[offset]) == Some(IcmpType::EchoRequest)
        {
            let old_src_mac = [
                packet[ethernet::SRC_MAC_OFFSET],
                packet[ethernet::SRC_MAC_OFFSET + 1],
                packet[ethernet::SRC_MAC_OFFSET + 2],
                packet[ethernet::SRC_MAC_OFFSET + 3],
                packet[ethernet::SRC_MAC_OFFSET + 4],
                packet[ethernet::SRC_MAC_OFFSET + 5],
            ];
            packet[0..ethernet::MAC_ADDR_SIZE].copy_from_slice(&old_src_mac);
            packet[ethernet::SRC_MAC_OFFSET..ethernet::SRC_MAC_OFFSET + ethernet::MAC_ADDR_SIZE]
                .copy_from_slice(&MAC_ADDR);

            let old_src_ip = [
                packet[ipv4::SRC_IP_OFFSET],
                packet[ipv4::SRC_IP_OFFSET + 1],
                packet[ipv4::SRC_IP_OFFSET + 2],
                packet[ipv4::SRC_IP_OFFSET + 3],
            ];
            packet[ipv4::SRC_IP_OFFSET..ipv4::SRC_IP_OFFSET + ipv4::IP_ADDR_SIZE]
                .copy_from_slice(&IP_ADDR);
            packet[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE]
                .copy_from_slice(&old_src_ip);

            packet[offset] = IcmpType::EchoReply as u8;
            packet[offset + 2] = 0;
            packet[offset + 3] = 0;

            let len = packet.len().min(MAX_ICMP_REPLY_LEN);
            let csum = checksum(&packet[offset..len]);
            packet[offset + 2] = (csum >> 8) as u8;
            packet[offset + 3] = (csum & 0xFF) as u8;

            sink.send(&packet[0..len]);
            return None;
        }
    }

    if IpProtocol::from_u8(protocol) == Some(IpProtocol::Tcp) {
        let offset = ipv4::HEADER_OFFSET + ihl as usize;
        if offset + tcp::MIN_HEADER_SIZE > packet.len() {
            return None;
        }

        // Parse flags and the TCP header length *before* any mutation
        // so we can decide whether to emit a SYN-ACK (which rewrites
        // `packet` in place) or hand the TCP application payload back
        // to the caller for DPI / firewall inspection.
        let dof_flags_be =
            ((packet[offset + 12] as u16) << 8) | (packet[offset + 13] as u16);
        let flags = dof_flags_be & 0x003F;
        let tcp_header_len = (((dof_flags_be >> 12) & 0x0F) as usize) * 4;

        if (flags & TCP_SYN) != 0 {
            let src_ip = [
                packet[ipv4::SRC_IP_OFFSET],
                packet[ipv4::SRC_IP_OFFSET + 1],
                packet[ipv4::SRC_IP_OFFSET + 2],
                packet[ipv4::SRC_IP_OFFSET + 3],
            ];
            let dst_ip = [
                packet[ipv4::DST_IP_OFFSET],
                packet[ipv4::DST_IP_OFFSET + 1],
                packet[ipv4::DST_IP_OFFSET + 2],
                packet[ipv4::DST_IP_OFFSET + 3],
            ];
            handle_tcp(packet, offset, &src_ip, &dst_ip, sink, syn_secret);
            return None;
        }

        let payload_offset = offset + tcp_header_len;
        return if payload_offset <= packet.len() {
            Some(&packet[payload_offset..])
        } else {
            None
        };
    }

    let payload_offset = ipv4::HEADER_OFFSET + ihl as usize;
    if payload_offset < packet.len() {
        Some(&packet[payload_offset..])
    } else {
        None
    }
}

/// Handles TCP packets with SYN flood protection.
///
/// Implements SYN cookies to protect against SYN flood attacks.
/// When a SYN packet is received, generates a SYN-ACK response
/// without maintaining connection state.
///
/// # Arguments
///
/// * `packet` - TCP packet buffer
/// * `offset` - Byte offset to the TCP header
/// * `src_ip` - Source IP address for cookie generation
/// * `dst_ip` - Destination IP (this kernel) for cookie binding
/// * `sink`   - Egress for the SYN-ACK reply
/// * `syn_secret` - Per-boot secret keying the cookie PRF
fn handle_tcp<S: PacketSink>(
    packet: &mut [u8],
    offset: usize,
    src_ip: &[u8; 4],
    dst_ip: &[u8; 4],
    sink: &mut S,
    syn_secret: &SynCookieSecret,
) {
    // SAFETY: The caller has verified packet.len() >= offset + size_of::<TcpHeader>(),
    // and the packet slice is valid for reads.
    let tcp = unsafe { &*(packet.as_ptr().add(offset).cast::<TcpHeader>()) };
    let flags = u16::from_be(tcp.data_offset_flags) & 0x003F;

    if (flags & TCP_SYN) != 0 {
        let seq = u32::from_be(tcp.seq_num);
        let src_port = u16::from_be(tcp.src_port);
        let dst_port = u16::from_be(tcp.dst_port);
        let cookie = syn_secret.cookie(src_ip, dst_ip, src_port, dst_port);

        // TCP sequence numbers wrap (RFC 793 §3.3); a SYN with
        // seq=0xFFFFFFFF is legal, so the ACK must wrap to 0 instead
        // of overflowing. Found by fuzzer crash 1.
        send_tcp_reply_inplace(
            packet,
            offset,
            cookie,
            seq.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            sink,
        );
    }
}

/// Constructs and sends a TCP reply packet in-place.
///
/// Modifies the original packet buffer to create a TCP response by
/// swapping MAC and IP addresses, constructing a new TCP header,
/// and sending the result. Used for SYN-ACK responses.
///
/// # Arguments
///
/// * `packet` - Packet buffer to modify
/// * `tcp_offset` - Byte offset to the TCP header
/// * `seq` - Sequence number for the reply
/// * `ack` - Acknowledgment number for the reply
/// * `flags` - TCP flags to set in the reply
fn send_tcp_reply_inplace<S: PacketSink>(
    packet: &mut [u8],
    tcp_offset: usize,
    seq: u32,
    ack: u32,
    flags: u16,
    sink: &mut S,
) {
    let old_src_mac = [
        packet[ethernet::SRC_MAC_OFFSET],
        packet[ethernet::SRC_MAC_OFFSET + 1],
        packet[ethernet::SRC_MAC_OFFSET + 2],
        packet[ethernet::SRC_MAC_OFFSET + 3],
        packet[ethernet::SRC_MAC_OFFSET + 4],
        packet[ethernet::SRC_MAC_OFFSET + 5],
    ];
    packet[0..ethernet::MAC_ADDR_SIZE].copy_from_slice(&old_src_mac);
    packet[ethernet::SRC_MAC_OFFSET..ethernet::SRC_MAC_OFFSET + ethernet::MAC_ADDR_SIZE]
        .copy_from_slice(&MAC_ADDR);

    let old_src_ip = [
        packet[ipv4::SRC_IP_OFFSET],
        packet[ipv4::SRC_IP_OFFSET + 1],
        packet[ipv4::SRC_IP_OFFSET + 2],
        packet[ipv4::SRC_IP_OFFSET + 3],
    ];
    packet[ipv4::SRC_IP_OFFSET..ipv4::SRC_IP_OFFSET + ipv4::IP_ADDR_SIZE].copy_from_slice(&IP_ADDR);
    packet[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE]
        .copy_from_slice(&old_src_ip);

    let orig_dst_port;
    let orig_src_port;
    {
        // SAFETY: The caller has verified packet.len() >= tcp_offset + size_of::<TcpHeader>(),
        // and the packet slice is valid for reads.
        let orig_tcp = unsafe { &*(packet.as_ptr().add(tcp_offset).cast::<TcpHeader>()) };
        orig_dst_port = orig_tcp.dst_port;
        orig_src_port = orig_tcp.src_port;
    }

    let reply_tcp = TcpHeader::new(
        u16::from_be(orig_dst_port),
        u16::from_be(orig_src_port),
        seq,
        ack,
        flags,
    );

    // SAFETY: packet.len() >= tcp_offset + size_of::<TcpHeader>() was verified by the caller,
    // and the packet slice is valid for writes.
    unsafe {
        let ptr = packet.as_mut_ptr().add(tcp_offset).cast::<TcpHeader>();
        *ptr = reply_tcp;
    }

    sink.send(&packet[0..tcp_offset + tcp::MIN_HEADER_SIZE]);
}

/// Calculates the Internet checksum for protocol headers.
///
/// Implements the standard one's complement checksum algorithm.
///
/// # Arguments
///
/// * `data` - Data buffer to checksum
///
/// # Returns
///
/// 16-bit checksum value
pub fn checksum(data: &[u8]) -> u16 {
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

