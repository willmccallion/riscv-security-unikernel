//! Builds the alert and telemetry frames the engine sends to the operator.
//!
//! Alerts carry a fixed-size metadata record and never echo inbound
//! payload bytes, so the mgmt network is not a relay for attacker data.

use super::OperatorAddr;
use crate::config::{IP_ADDR, MAC_ADDR, MANAGEMENT_PORT, TELEMETRY_PORT};
use crate::net::constants::{BROADCAST_MAC, IpProtocol, ethernet, ipv4, udp};
use crate::net::stack::checksum;
use crate::security::alert::{AlertMeta, AlertReason, alert_packet};

/// IPv4 broadcast fallback used before the operator address is learned.
const BROADCAST_IP: [u8; 4] = [192, 168, 100, 255];

const UDP_OFFSET: usize = ipv4::HEADER_OFFSET + ipv4::MIN_HEADER_SIZE;
const UDP_PAYLOAD_OFFSET: usize = UDP_OFFSET + udp::HEADER_SIZE;
const IP_CHECKSUM_OFFSET: usize = ipv4::HEADER_OFFSET + 10;

/// Number of u64 counters in a telemetry frame.
const TELEMETRY_SLOTS: usize = 10;

/// Length of an alert frame on the wire.
pub const ALERT_FRAME_LEN: usize = UDP_PAYLOAD_OFFSET + alert_packet::ALERT_BODY_LEN;
/// Length of a telemetry frame on the wire.
pub const TELEMETRY_FRAME_LEN: usize = UDP_PAYLOAD_OFFSET + TELEMETRY_SLOTS * 8;

/// Writes an alert frame into `buf` and returns it.
pub fn alert_frame<'a>(
    buf: &'a mut [u8; ALERT_FRAME_LEN],
    operator: Option<OperatorAddr>,
    meta: &AlertMeta,
    reason: AlertReason,
) -> &'a [u8] {
    write_udp_headers(&mut buf[..], operator, MANAGEMENT_PORT, TELEMETRY_PORT);
    let body = &mut buf[UDP_PAYLOAD_OFFSET..];
    body[0] = alert_packet::ALERT_MESSAGE_TYPE;
    body[alert_packet::REASON_OFFSET] = reason.as_u8();
    body[alert_packet::SRC_IP_OFFSET..alert_packet::SRC_IP_OFFSET + 4].copy_from_slice(&meta.src_ip);
    body[alert_packet::DST_IP_OFFSET..alert_packet::DST_IP_OFFSET + 4].copy_from_slice(&meta.dst_ip);
    body[alert_packet::SRC_PORT_OFFSET..alert_packet::SRC_PORT_OFFSET + 2]
        .copy_from_slice(&meta.src_port.to_be_bytes());
    body[alert_packet::DST_PORT_OFFSET..alert_packet::DST_PORT_OFFSET + 2]
        .copy_from_slice(&meta.dst_port.to_be_bytes());
    body[alert_packet::PROTOCOL_OFFSET] = meta.protocol;
    body[alert_packet::PACKET_LEN_OFFSET..alert_packet::PACKET_LEN_OFFSET + 2]
        .copy_from_slice(&meta.packet_len.to_be_bytes());
    &buf[..]
}

/// Writes a telemetry frame carrying `slots` into `buf` and returns it.
pub fn telemetry_frame<'a>(
    buf: &'a mut [u8; TELEMETRY_FRAME_LEN],
    operator: Option<OperatorAddr>,
    slots: &[u64; TELEMETRY_SLOTS],
) -> &'a [u8] {
    write_udp_headers(&mut buf[..], operator, TELEMETRY_PORT, TELEMETRY_PORT);
    let (chunks, _) = buf[UDP_PAYLOAD_OFFSET..].as_chunks_mut::<8>();
    for (chunk, value) in chunks.iter_mut().zip(slots) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    &buf[..]
}

/// Fills the Ethernet, IPv4 and UDP headers for a frame that spans all of
/// `frame`, addressed to the operator or, before one is known, broadcast.
fn write_udp_headers(frame: &mut [u8], operator: Option<OperatorAddr>, src_port: u16, dst_port: u16) {
    let (dst_mac, dst_ip) = operator.map_or((BROADCAST_MAC, BROADCAST_IP), |op| (op.mac, op.ip));
    let ip_len = (frame.len() - ipv4::HEADER_OFFSET) as u16;
    let udp_len = (frame.len() - UDP_OFFSET) as u16;

    frame[..ethernet::MAC_ADDR_SIZE].copy_from_slice(&dst_mac);
    frame[ethernet::SRC_MAC_OFFSET..ethernet::SRC_MAC_OFFSET + ethernet::MAC_ADDR_SIZE]
        .copy_from_slice(&MAC_ADDR);
    frame[ethernet::TYPE_OFFSET..ethernet::TYPE_OFFSET + 2].copy_from_slice(&[0x08, 0x00]);

    let ip = &mut frame[ipv4::HEADER_OFFSET..UDP_OFFSET];
    ip[0] = ipv4::VERSION;
    ip[1] = 0;
    ip[2..4].copy_from_slice(&ip_len.to_be_bytes());
    ip[4..6].copy_from_slice(&[0, 0]);
    // Don't Fragment.
    ip[6..8].copy_from_slice(&[0x40, 0x00]);
    ip[8] = ipv4::DEFAULT_TTL;
    ip[9] = IpProtocol::Udp as u8;
    ip[10..12].copy_from_slice(&[0, 0]);
    ip[12..16].copy_from_slice(&IP_ADDR);
    ip[16..20].copy_from_slice(&dst_ip);
    let csum = checksum(&frame[ipv4::HEADER_OFFSET..UDP_OFFSET]);
    frame[IP_CHECKSUM_OFFSET..IP_CHECKSUM_OFFSET + 2].copy_from_slice(&csum.to_be_bytes());

    let udp = &mut frame[UDP_OFFSET..UDP_PAYLOAD_OFFSET];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].copy_from_slice(&[0, 0]);
}
