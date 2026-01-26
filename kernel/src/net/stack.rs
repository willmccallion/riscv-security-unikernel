//! Network protocol stack for packet processing.
//!
//! Handles Ethernet, IPv4, ARP, ICMP, and TCP protocols. Processes
//! incoming packets, generates responses where appropriate, and
//! extracts payload data for security inspection.

use crate::config::{IP_ADDR, MAC_ADDR};
use crate::drivers::net_device::NetDevice;
use crate::net::constants::MAX_ICMP_REPLY_LEN;
use crate::net::constants::SYN_COOKIE_MAGIC;
use crate::net::constants::{
    ArpOpcode, EthernetType, IcmpType, IpProtocol, arp, ethernet, ipv4, tcp,
};
use crate::net::tcp::{TCP_ACK, TCP_SYN, TcpHeader};

/// Processes an incoming network packet.
///
/// Handles various protocol types:
/// - ARP: Generates ARP replies for address resolution
/// - ICMP: Responds to ping requests
/// - TCP: Handles SYN packets with SYN cookies
/// - Other IPv4: Extracts payload for security inspection
///
/// The packet buffer may be modified in-place for generating responses.
///
/// # Arguments
///
/// * `packet` - Mutable reference to the packet buffer
///
/// # Returns
///
/// Some immutable slice to payload data if available, None if the
/// packet was consumed (e.g., ARP reply sent) or invalid.
pub fn process_packet(packet: &mut [u8]) -> Option<&[u8]> {
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
            handle_arp(packet);
            None
        }
        Some(EthernetType::Ipv4) => handle_ipv4(packet),
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
fn handle_arp(packet: &mut [u8]) {
    if packet.len() < arp::MIN_PACKET_SIZE {
        return;
    }
    let hw_type = packet[arp::HW_TYPE_OFFSET];
    let opcode = packet[arp::OPCODE_OFFSET];
    if hw_type != 0 || ArpOpcode::from_u16(opcode as u16) != Some(ArpOpcode::Request) {
        return;
    }
    if &packet[arp::TARGET_IP_OFFSET..arp::TARGET_IP_OFFSET + ipv4::IP_ADDR_SIZE] != IP_ADDR {
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

    packet[arp::OPCODE_OFFSET] = ArpOpcode::Reply as u8;

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

    NetDevice::send(&packet[0..arp::MIN_PACKET_SIZE]);
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
fn handle_ipv4(packet: &mut [u8]) -> Option<&[u8]> {
    if packet.len() < ipv4::HEADER_OFFSET + ipv4::MIN_HEADER_SIZE {
        return None;
    }
    let ihl = (packet[ipv4::VERSION_IHL_OFFSET] & ipv4::IHL_MASK) * 4;
    let protocol = packet[ipv4::PROTOCOL_OFFSET];

    if &packet[ipv4::DST_IP_OFFSET..ipv4::DST_IP_OFFSET + ipv4::IP_ADDR_SIZE] != IP_ADDR {
        return None;
    }

    if IpProtocol::from_u8(protocol) == Some(IpProtocol::Icmp) {
        let offset = ipv4::HEADER_OFFSET + ihl as usize;
        if offset < packet.len() && IcmpType::from_u8(packet[offset]) == Some(IcmpType::EchoRequest)
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

            NetDevice::send(&packet[0..len]);
            return None;
        }
    }

    if IpProtocol::from_u8(protocol) == Some(IpProtocol::Tcp) {
        let offset = ipv4::HEADER_OFFSET + ihl as usize;
        if offset + tcp::MIN_HEADER_SIZE <= packet.len() {
            let src_ip = [
                packet[ipv4::SRC_IP_OFFSET],
                packet[ipv4::SRC_IP_OFFSET + 1],
                packet[ipv4::SRC_IP_OFFSET + 2],
                packet[ipv4::SRC_IP_OFFSET + 3],
            ];
            handle_tcp(packet, offset, &src_ip);
        }
        return None;
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
fn handle_tcp(packet: &mut [u8], offset: usize, src_ip: &[u8]) {
    let tcp = unsafe { &*(packet.as_ptr().add(offset) as *const TcpHeader) };
    let flags = u16::from_be(tcp.data_offset_flags) & 0x003F;

    if (flags & TCP_SYN) != 0 {
        let seq = u32::from_be(tcp.seq_num);
        let cookie = (src_ip[3] as u32) + (u16::from_be(tcp.src_port) as u32) + SYN_COOKIE_MAGIC;

        send_tcp_reply_inplace(packet, offset, cookie, seq + 1, TCP_SYN | TCP_ACK);
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
fn send_tcp_reply_inplace(packet: &mut [u8], tcp_offset: usize, seq: u32, ack: u32, flags: u16) {
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
        let orig_tcp = unsafe { &*(packet.as_ptr().add(tcp_offset) as *const TcpHeader) };
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

    unsafe {
        let ptr = packet.as_mut_ptr().add(tcp_offset) as *mut TcpHeader;
        *ptr = reply_tcp;
    }

    NetDevice::send(&packet[0..tcp_offset + tcp::MIN_HEADER_SIZE]);
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
fn checksum(data: &[u8]) -> u16 {
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
