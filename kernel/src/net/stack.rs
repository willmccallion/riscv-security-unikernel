use crate::config::{IP_ADDR, MAC_ADDR};
use crate::drivers::net_device::NetDevice;
use crate::net::tcp::{TCP_ACK, TCP_SYN, TcpHeader};

// Accept mutable reference to allow in-place modification
pub fn process_packet(packet: &mut [u8]) -> Option<&[u8]> {
    if packet.len() < 14 {
        return None;
    }
    let eth_type = (packet[12] as u16) << 8 | packet[13] as u16;
    match eth_type {
        0x0806 => {
            handle_arp(packet);
            None // Packet consumed/replied
        }
        0x0800 => handle_ipv4(packet),
        _ => None,
    }
}

// Modifies the RX buffer in-place to create the TX packet
fn handle_arp(packet: &mut [u8]) {
    if packet.len() < 42 {
        return;
    }
    // Check if request (1) and target IP matches
    if packet[20] != 0 || packet[21] != 1 {
        return;
    }
    if &packet[38..42] != IP_ADDR {
        return;
    }

    // Swap ethernet MACs
    // Dst MAC = old src MAC
    let old_src_mac = [
        packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
    ];
    packet[0..6].copy_from_slice(&old_src_mac);
    // Src MAC = our MAC
    packet[6..12].copy_from_slice(&MAC_ADDR);

    // Set ARP opcode to reply (2)
    packet[21] = 2;

    // Swap ARP payload
    let old_sender_ip = [packet[28], packet[29], packet[30], packet[31]];

    // Target MAC = old sender MAC
    packet[32..38].copy_from_slice(&old_src_mac);
    // Target IP = old sender IP
    packet[38..42].copy_from_slice(&old_sender_ip);

    // Sender MAC = our MAC
    packet[22..28].copy_from_slice(&MAC_ADDR);
    // Sender IP = our IP
    packet[28..32].copy_from_slice(&IP_ADDR);

    // Send modified buffer
    NetDevice::send(&packet[0..42]);
}

fn handle_ipv4(packet: &mut [u8]) -> Option<&[u8]> {
    if packet.len() < 34 {
        return None;
    }
    let ihl = (packet[14] & 0x0F) * 4;
    let protocol = packet[23];

    // Check destination IP
    if &packet[30..34] != IP_ADDR {
        return None;
    }

    // ICMP echo (Ping)
    if protocol == 1 {
        let offset = 14 + ihl as usize;
        if offset < packet.len() && packet[offset] == 8 {
            // Swap ethernet MACs
            let old_src_mac = [
                packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
            ];
            packet[0..6].copy_from_slice(&old_src_mac);
            packet[6..12].copy_from_slice(&MAC_ADDR);

            // Swap IP addresses
            let old_src_ip = [packet[26], packet[27], packet[28], packet[29]];
            packet[26..30].copy_from_slice(&IP_ADDR); // Src = Us
            packet[30..34].copy_from_slice(&old_src_ip); // Dst = Them

            // Modify ICMP header
            packet[offset] = 0; // Type 0 (Reply)
            // Reset checksum field to 0 before recalc
            packet[offset + 2] = 0;
            packet[offset + 3] = 0;

            // Calculate checksum
            let len = packet.len().min(128); // Cap length for safety
            let csum = checksum(&packet[offset..len]);
            packet[offset + 2] = (csum >> 8) as u8;
            packet[offset + 3] = (csum & 0xFF) as u8;

            NetDevice::send(&packet[0..len]);
            return None;
        }
    }

    // TCP processing (SYN cookies)
    if protocol == 6 {
        let offset = 14 + ihl as usize;
        if offset + 20 <= packet.len() {
            let src_ip = [packet[26], packet[27], packet[28], packet[29]];
            handle_tcp(packet, offset, &src_ip);
        }
        return None; // Don't forward TCP to userspace logic yet
    }

    let payload_offset = 14 + ihl as usize;
    if payload_offset < packet.len() {
        // Return immutable slice for inspection
        Some(&packet[payload_offset..])
    } else {
        None
    }
}

fn handle_tcp(packet: &mut [u8], offset: usize, src_ip: &[u8]) {
    // Unsafe cast to read header
    let tcp = unsafe { &*(packet.as_ptr().add(offset) as *const TcpHeader) };
    let flags = u16::from_be(tcp.data_offset_flags) & 0x003F;

    // SYN flood protection (SYN cookies)
    if (flags & TCP_SYN) != 0 {
        let seq = u32::from_be(tcp.seq_num);
        let cookie = (src_ip[3] as u32) + (u16::from_be(tcp.src_port) as u32) + 0xCAFEBABE;

        // Send SYN-ACK
        send_tcp_reply_inplace(
            packet,
            offset,
            cookie,  // Our Seq
            seq + 1, // Ack
            TCP_SYN | TCP_ACK,
        );
    }
}

fn send_tcp_reply_inplace(packet: &mut [u8], tcp_offset: usize, seq: u32, ack: u32, flags: u16) {
    // Swap ethernet MACs
    let old_src_mac = [
        packet[6], packet[7], packet[8], packet[9], packet[10], packet[11],
    ];
    packet[0..6].copy_from_slice(&old_src_mac);
    packet[6..12].copy_from_slice(&MAC_ADDR);

    // Swap IP addresses
    let old_src_ip = [packet[26], packet[27], packet[28], packet[29]];
    packet[26..30].copy_from_slice(&IP_ADDR);
    packet[30..34].copy_from_slice(&old_src_ip);

    // Construct new TCP header
    // We need to read ports before overwriting
    let orig_dst_port;
    let orig_src_port;
    {
        let orig_tcp = unsafe { &*(packet.as_ptr().add(tcp_offset) as *const TcpHeader) };
        orig_dst_port = orig_tcp.dst_port; // Already BE
        orig_src_port = orig_tcp.src_port; // Already BE
    }

    let reply_tcp = TcpHeader::new(
        u16::from_be(orig_dst_port), // Swap ports: src = old dst
        u16::from_be(orig_src_port), // dst = old src
        seq,
        ack,
        flags,
    );

    // Overwrite TCP header
    unsafe {
        let ptr = packet.as_mut_ptr().add(tcp_offset) as *mut TcpHeader;
        *ptr = reply_tcp;
    }

    // Send (Ethernet(14) + IP(20) + TCP(20) = 54 bytes)
    // Assuming standard header sizes for simplicity in this optimization
    NetDevice::send(&packet[0..tcp_offset + 20]);
}

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
