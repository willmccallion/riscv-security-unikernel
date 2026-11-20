//! Builders and predicates for the Ethernet frames the harness exchanges.

use sec_core::config::{IP_ADDR, MAC_ADDR};
use sec_core::net::constants::{ArpOpcode, EthernetType, IpProtocol, arp, ethernet, ipv4, udp};
use sec_core::security::alert::AlertReason;
use sec_core::security::mgmt::Ack;
use sec_core::security::report_auth::{ReportBody, Telemetry};

/// The kernel's IPv4 address.
pub const KERNEL_IP: [u8; 4] = IP_ADDR.octets();
/// The kernel's MAC address.
pub const KERNEL_MAC: [u8; 6] = MAC_ADDR;
/// Address the harness presents as its own.
pub const HOST_IP: [u8; 4] = [192, 168, 100, 1];
/// MAC the harness presents as its own.
pub const HOST_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

const ETHERTYPE_IPV4: [u8; 2] = (EthernetType::Ipv4 as u16).to_be_bytes();
const ETHERTYPE_ARP: [u8; 2] = (EthernetType::Arp as u16).to_be_bytes();
const ETHERTYPE: core::ops::Range<usize> =
    ethernet::TYPE_OFFSET..ethernet::TYPE_OFFSET + ethernet::TYPE_SIZE;
/// Where the UDP header starts in the option-less frames both sides send.
const UDP_OFFSET: usize = ipv4::HEADER_OFFSET + ipv4::MIN_HEADER_SIZE;
pub(crate) const UDP_PAYLOAD_OFFSET: usize = UDP_OFFSET + udp::HEADER_SIZE;
const IPV4_HEADER: core::ops::Range<usize> = ipv4::HEADER_OFFSET..UDP_OFFSET;
const IPV4_CHECKSUM_OFFSET: usize = ipv4::HEADER_OFFSET + ipv4::field::CHECKSUM;

/// Builds an ARP request asking who has `target_ip`.
pub fn arp_request(target_ip: [u8; 4]) -> Vec<u8> {
    let mut f = Vec::with_capacity(arp::MIN_PACKET_SIZE);
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
    frame.len() >= arp::MIN_PACKET_SIZE
        && frame[ETHERTYPE] == ETHERTYPE_ARP
        && frame[arp::OPCODE_OFFSET..][..2] == (ArpOpcode::Reply as u16).to_be_bytes()
        && frame[arp::SENDER_MAC_OFFSET..][..ethernet::MAC_ADDR_SIZE] == KERNEL_MAC
}

/// Builds an Ethernet + IPv4 header (IHL 5) addressed to the kernel,
/// followed by `l4`. The IPv4 checksum is filled in.
pub fn ipv4_to_kernel(src_ip: [u8; 4], protocol: u8, l4: &[u8]) -> Vec<u8> {
    let total_len = u16::try_from(20 + l4.len()).unwrap_or(u16::MAX);
    let mut f = Vec::with_capacity(UDP_OFFSET + l4.len());
    f.extend_from_slice(&KERNEL_MAC);
    f.extend_from_slice(&HOST_MAC);
    f.extend_from_slice(&ETHERTYPE_IPV4);
    f.extend_from_slice(&[0x45, 0x00]);
    f.extend_from_slice(&total_len.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
    f.extend_from_slice(&src_ip);
    f.extend_from_slice(&KERNEL_IP);
    let csum = sec_core::net::stack::checksum(&f[IPV4_HEADER]);
    f[IPV4_CHECKSUM_OFFSET..][..2].copy_from_slice(&csum.to_be_bytes());
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
    ipv4_to_kernel(src_ip, IpProtocol::Udp as u8, &l4)
}

/// True if `frame` is a UDP datagram from the kernel to `dst_port`.
pub fn is_udp_from_kernel_to_port(frame: &[u8], dst_port: u16) -> bool {
    is_udp_from_kernel(frame)
        && frame[UDP_OFFSET + udp::DST_PORT_OFFSET..][..2] == dst_port.to_be_bytes()
}

/// True if `frame` is a whole UDP datagram header from the kernel.
fn is_udp_from_kernel(frame: &[u8]) -> bool {
    frame.len() >= UDP_PAYLOAD_OFFSET
        && frame[ETHERTYPE] == ETHERTYPE_IPV4
        && frame[ipv4::PROTOCOL_OFFSET] == IpProtocol::Udp as u8
        && frame[ipv4::SRC_IP_OFFSET..][..ipv4::IP_ADDR_SIZE] == KERNEL_IP
}

/// The body of a report from the kernel (telemetry, alert or ack), with
/// the UDP headers and signed envelope stripped. Does not check the MAC;
/// see [`crate::mgmt::MgmtClient::verify_report`] for that.
pub fn report_body(frame: &[u8]) -> Option<&[u8]> {
    use sec_core::security::report_auth::{HEADER_LEN, MAC_LEN};
    if !is_udp_from_kernel(frame) {
        return None;
    }
    frame.get(UDP_PAYLOAD_OFFSET + HEADER_LEN..frame.len().checked_sub(MAC_LEN)?)
}

/// The reason of the security alert in `frame`, if it is one from the
/// kernel.
pub fn alert_reason(frame: &[u8]) -> Option<AlertReason> {
    match ReportBody::parse(report_body(frame)?)? {
        ReportBody::Alert(alert) => Some(alert.reason),
        _ => None,
    }
}

/// The mgmt ack in `frame`, if it is one from the kernel.
pub fn mgmt_ack(frame: &[u8]) -> Option<Ack> {
    match ReportBody::parse(report_body(frame)?)? {
        ReportBody::Ack(ack) => Some(ack),
        _ => None,
    }
}

/// The telemetry in `frame`, if it is a report from the kernel.
pub fn telemetry(frame: &[u8]) -> Option<Telemetry> {
    match ReportBody::parse(report_body(frame)?)? {
        ReportBody::Telemetry(telemetry) => Some(telemetry),
        _ => None,
    }
}
