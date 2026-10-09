//! Builders and predicates for the Ethernet frames the harness exchanges.

use sec_core::config::{IP_ADDR, MAC_ADDR};

/// The kernel's IPv4 address.
pub const KERNEL_IP: [u8; 4] = IP_ADDR;
/// The kernel's MAC address.
pub const KERNEL_MAC: [u8; 6] = MAC_ADDR;
/// Address the harness presents as its own.
pub const HOST_IP: [u8; 4] = [192, 168, 100, 1];
/// MAC the harness presents as its own.
pub const HOST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];

/// Builds an ARP request asking who has `target_ip`.
pub fn arp_request(target_ip: [u8; 4]) -> Vec<u8> {
    let mut f = Vec::with_capacity(42);
    f.extend_from_slice(&[0xFF; 6]);
    f.extend_from_slice(&HOST_MAC);
    f.extend_from_slice(&ETHERTYPE_ARP);
    f.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]);
    f.extend_from_slice(&HOST_MAC);
    f.extend_from_slice(&HOST_IP);
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&target_ip);
    f
}

/// True if `frame` is an ARP reply sent by the kernel.
pub fn is_arp_reply_from_kernel(frame: &[u8]) -> bool {
    frame.len() >= 42
        && frame[12..14] == ETHERTYPE_ARP
        && frame[20..22] == [0x00, 0x02]
        && frame[22..28] == KERNEL_MAC
}

/// Builds an Ethernet + IPv4 header (IHL 5) addressed to the kernel,
/// followed by `l4`. The IPv4 checksum is filled in.
pub fn ipv4_to_kernel(src_ip: [u8; 4], protocol: u8, l4: &[u8]) -> Vec<u8> {
    let total_len = u16::try_from(20 + l4.len()).unwrap_or(u16::MAX);
    let mut f = Vec::with_capacity(34 + l4.len());
    f.extend_from_slice(&KERNEL_MAC);
    f.extend_from_slice(&HOST_MAC);
    f.extend_from_slice(&ETHERTYPE_IPV4);
    f.extend_from_slice(&[0x45, 0x00]);
    f.extend_from_slice(&total_len.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
    f.extend_from_slice(&src_ip);
    f.extend_from_slice(&KERNEL_IP);
    let csum = sec_core::net::stack::checksum(&f[14..34]);
    f[24..26].copy_from_slice(&csum.to_be_bytes());
    f.extend_from_slice(l4);
    f
}

/// Builds a UDP datagram from `src_ip:src_port` to the kernel's `dst_port`.
pub fn udp_to_kernel(src_ip: [u8; 4], src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = u16::try_from(8 + payload.len()).unwrap_or(u16::MAX);
    let mut l4 = Vec::with_capacity(8 + payload.len());
    l4.extend_from_slice(&src_port.to_be_bytes());
    l4.extend_from_slice(&dst_port.to_be_bytes());
    l4.extend_from_slice(&udp_len.to_be_bytes());
    l4.extend_from_slice(&[0, 0]);
    l4.extend_from_slice(payload);
    ipv4_to_kernel(src_ip, 17, &l4)
}

/// True if `frame` is a UDP datagram from the kernel to `dst_port`.
pub fn is_udp_from_kernel_to_port(frame: &[u8], dst_port: u16) -> bool {
    frame.len() >= 42
        && frame[12..14] == ETHERTYPE_IPV4
        && frame[23] == 17
        && frame[26..30] == KERNEL_IP
        && frame[36..38] == dst_port.to_be_bytes()
}

/// Returns the alert reason code if `frame` is a security alert from the
/// kernel.
pub fn alert_reason(frame: &[u8]) -> Option<u8> {
    use sec_core::security::alert::alert_packet::{ALERT_MESSAGE_TYPE, REASON_OFFSET};
    let is_alert = frame.len() > 42 + REASON_OFFSET
        && frame[12..14] == ETHERTYPE_IPV4
        && frame[23] == 17
        && frame[26..30] == KERNEL_IP
        && frame[42] == ALERT_MESSAGE_TYPE;
    is_alert.then(|| frame[42 + REASON_OFFSET])
}
