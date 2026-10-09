//! Network protocol stack for packet processing.
//!
//! Handles Ethernet, IPv4, ARP, ICMP, and TCP protocols. Processes
//! incoming packets, generates responses where appropriate, and
//! extracts payload data for security inspection.

use crate::config::{IP_ADDR, MAC_ADDR};
use crate::net::PacketSink;
use crate::net::constants::{
    ArpOpcode, EthernetType, IcmpType, IpProtocol, arp, ethernet, ipv4, tcp,
};
use crate::net::tcp::{TCP_ACK, TCP_SYN};
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
    // Reject anything that isn't a well-formed IPv4 header. Accepting
    // version != 4 or IHL < 5 lets a sender position the "TCP header"
    // inside the IP header itself, so downstream port/firewall checks
    // run on the wrong bytes -- a packet to a banned port can sneak
    // past by claiming IHL=0 and having the firewall match against
    // header bytes that happen to look like a different port.
    let version_ihl = packet[ipv4::VERSION_IHL_OFFSET];
    if (version_ihl >> 4) != 4 {
        return None;
    }
    let ihl_words = version_ihl & ipv4::IHL_MASK;
    if ihl_words < 5 {
        return None;
    }
    let ihl = ihl_words * 4;
    let protocol = packet[ipv4::PROTOCOL_OFFSET];

    if packet[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE] != IP_ADDR {
        return None;
    }

    if IpProtocol::from_u8(protocol) == Some(IpProtocol::Icmp) {
        let offset = ipv4::HEADER_OFFSET + ihl as usize;
        // Type, code and checksum are rewritten in place.
        const ICMP_HEADER_MIN: usize = 4;
        if let Some(ip_end) = ipv4_end(packet, usize::from(ihl))
            && offset + ICMP_HEADER_MIN <= ip_end
            && IcmpType::from_u8(packet[offset]) == Some(IcmpType::EchoRequest)
        {
            swap_addresses(packet);
            packet[offset] = IcmpType::EchoReply as u8;
            packet[offset + 2..offset + 4].copy_from_slice(&[0, 0]);
            let csum = checksum(&packet[offset..ip_end]);
            packet[offset + 2..offset + 4].copy_from_slice(&csum.to_be_bytes());
            finish_ipv4_header(packet, usize::from(ihl), ip_end - ipv4::HEADER_OFFSET);
            sink.send(&packet[..ip_end]);
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
        // Same shape as the IHL check above: a data-offset under 5
        // (= 20 bytes) lets the "payload" returned to DPI / firewall
        // start inside the TCP header, which makes port-based rules
        // trivially evadable.
        if tcp_header_len < tcp::MIN_HEADER_SIZE {
            return None;
        }

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
    // The TCP header lives at an offset of `14 + IHL` from the packet
    // start, where IHL is variable. Casting `packet.as_ptr().add(offset)`
    // to `&TcpHeader` would be sound under `#[repr(C, packed)]` (the
    // resulting reference is alignment-1), but on real RV64GC silicon
    // without hardware misaligned-access support the struct-assignment
    // store the reply path used to do would trap to an absent `mtvec`
    // handler and jump to garbage. Read field-by-field via byte slices
    // so the compiler always emits per-byte loads, matching what the
    // rest of this file does for IPv4 / Ethernet / ARP.
    let tcp = &packet[offset..offset + tcp::MIN_HEADER_SIZE];
    let flags = u16::from_be_bytes([tcp[12], tcp[13]]) & 0x003F;

    if (flags & TCP_SYN) != 0 {
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
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
    /// Default TCP receive-window size advertised in SYN-ACK replies.
    /// The SYN-cookie path keeps no per-flow state, so this is fixed.
    const REPLY_WINDOW: u16 = 64240;
    /// Header length encoded in the data-offset nibble (5 × 4 = 20 bytes).
    const DATA_OFFSET_5: u16 = 5 << 12;

    let (reply_dst_port, reply_src_port) = {
        let orig = &packet[tcp_offset..tcp_offset + tcp::MIN_HEADER_SIZE];
        (
            u16::from_be_bytes([orig[0], orig[1]]),
            u16::from_be_bytes([orig[2], orig[3]]),
        )
    };
    swap_addresses(packet);

    let reply_end = tcp_offset + tcp::MIN_HEADER_SIZE;
    let reply = &mut packet[tcp_offset..reply_end];
    reply[0..2].copy_from_slice(&reply_src_port.to_be_bytes());
    reply[2..4].copy_from_slice(&reply_dst_port.to_be_bytes());
    reply[4..8].copy_from_slice(&seq.to_be_bytes());
    reply[8..12].copy_from_slice(&ack.to_be_bytes());
    reply[12..14].copy_from_slice(&(DATA_OFFSET_5 | flags).to_be_bytes());
    reply[14..16].copy_from_slice(&REPLY_WINDOW.to_be_bytes());
    reply[16..20].copy_from_slice(&[0, 0, 0, 0]);
    let csum = tcp_checksum(packet, tcp_offset..reply_end);
    packet[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&csum.to_be_bytes());

    let ihl = tcp_offset - ipv4::HEADER_OFFSET;
    finish_ipv4_header(packet, ihl, reply_end - ipv4::HEADER_OFFSET);
    sink.send(&packet[..reply_end]);
}

/// End of the IPv4 datagram within the frame, from its total-length field,
/// or `None` if that length is shorter than the header or longer than the
/// frame.
fn ipv4_end(packet: &[u8], ihl: usize) -> Option<usize> {
    let total = usize::from(u16::from_be_bytes([packet[16], packet[17]]));
    let end = ipv4::HEADER_OFFSET + total;
    (total >= ihl && end <= packet.len()).then_some(end)
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
    packet[ipv4::SRC_IP_OFFSET..ipv4::SRC_IP_OFFSET + ipv4::IP_ADDR_SIZE].copy_from_slice(&IP_ADDR);
    packet[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE].copy_from_slice(&peer_ip);
}

/// Sets the total length and a fresh TTL on an outgoing IPv4 header of
/// `ihl` bytes, then recomputes its checksum.
fn finish_ipv4_header(packet: &mut [u8], ihl: usize, total_len: usize) {
    const TOTAL_LEN_OFFSET: usize = ipv4::HEADER_OFFSET + 2;
    const TTL_OFFSET: usize = ipv4::HEADER_OFFSET + 8;
    const CHECKSUM_OFFSET: usize = ipv4::HEADER_OFFSET + 10;
    packet[TOTAL_LEN_OFFSET..TOTAL_LEN_OFFSET + 2].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[TTL_OFFSET] = ipv4::DEFAULT_TTL;
    packet[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 2].copy_from_slice(&[0, 0]);
    let csum = checksum(&packet[ipv4::HEADER_OFFSET..ipv4::HEADER_OFFSET + ihl]);
    packet[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 2].copy_from_slice(&csum.to_be_bytes());
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

