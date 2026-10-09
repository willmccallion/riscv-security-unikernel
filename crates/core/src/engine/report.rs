//! Builds the signed report frames the engine sends to the operator.
//!
//! Every report (alert, mgmt ack or telemetry) is a UDP datagram whose
//! payload is a [`report_auth`](crate::security::report_auth) envelope.
//! Alerts carry a fixed-size metadata record and never echo inbound
//! payload bytes, so the mgmt network is not a relay for attacker data.

use super::OperatorAddr;
use crate::config::{IP_ADDR, MAC_ADDR};
use crate::net::constants::{BROADCAST_MAC, IpProtocol, ethernet, ipv4, udp};
use crate::net::stack::checksum;
use crate::security::alert::{AlertMeta, AlertReason, alert_packet};
use crate::security::mgmt::{MgmtOutcome, ack_packet};
use crate::security::report_auth::{self, telemetry_packet};

/// IPv4 broadcast fallback used before the operator address is learned.
const BROADCAST_IP: [u8; 4] = [192, 168, 100, 255];

const UDP_OFFSET: usize = ipv4::HEADER_OFFSET + ipv4::MIN_HEADER_SIZE;
const UDP_PAYLOAD_OFFSET: usize = UDP_OFFSET + udp::HEADER_SIZE;
const IP_CHECKSUM_OFFSET: usize = ipv4::HEADER_OFFSET + 10;

/// Length of the largest report frame, a telemetry report.
pub const MAX_REPORT_FRAME_LEN: usize =
    UDP_PAYLOAD_OFFSET + report_auth::OVERHEAD + telemetry_packet::BODY_LEN;

/// Who signs a report and where it goes.
#[derive(Debug, Clone, Copy)]
pub struct ReportHeader<'a> {
    /// Unicast destination, or `None` to broadcast.
    pub operator: Option<OperatorAddr>,
    /// UDP source port.
    pub src_port: u16,
    /// UDP destination port.
    pub dst_port: u16,
    /// Report-signing key.
    pub key: &'a [u8; 16],
    /// Boot epoch.
    pub epoch: u32,
    /// Position in this boot's report stream.
    pub seq: u64,
}

/// Body of an alert report.
pub fn alert_body(meta: &AlertMeta, reason: AlertReason) -> [u8; alert_packet::ALERT_BODY_LEN] {
    let mut body = [0u8; alert_packet::ALERT_BODY_LEN];
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
    body[alert_packet::PREFIX_LEN_OFFSET] = meta.prefix_len;
    body[alert_packet::VALUE_OFFSET..alert_packet::VALUE_OFFSET + 4].copy_from_slice(&meta.value.to_be_bytes());
    body
}

/// Body of an ack for the command `seq` of type `command`.
pub fn ack_body(seq: u32, command: u8, outcome: MgmtOutcome) -> [u8; ack_packet::ACK_BODY_LEN] {
    let mut body = [0u8; ack_packet::ACK_BODY_LEN];
    body[0] = ack_packet::ACK_MESSAGE_TYPE;
    body[ack_packet::SEQ_OFFSET..ack_packet::SEQ_OFFSET + 4].copy_from_slice(&seq.to_be_bytes());
    body[ack_packet::COMMAND_OFFSET] = command;
    body[ack_packet::OUTCOME_OFFSET] = outcome as u8;
    body
}

/// Body of a telemetry report carrying `slots`.
pub fn telemetry_body(slots: &[u64; telemetry_packet::SLOTS]) -> [u8; telemetry_packet::BODY_LEN] {
    let mut body = [0u8; telemetry_packet::BODY_LEN];
    body[0] = telemetry_packet::MESSAGE_TYPE;
    let (chunks, _) = body[telemetry_packet::SLOTS_OFFSET..].as_chunks_mut::<8>();
    for (chunk, value) in chunks.iter_mut().zip(slots) {
        chunk.copy_from_slice(&value.to_be_bytes());
    }
    body
}

/// Writes `body` as a signed report frame into `buf` and returns the
/// frame.
pub fn report_frame<'a>(
    buf: &'a mut [u8; MAX_REPORT_FRAME_LEN],
    header: &ReportHeader<'_>,
    body: &[u8],
) -> &'a [u8] {
    let len = UDP_PAYLOAD_OFFSET + report_auth::OVERHEAD + body.len();
    let frame = &mut buf[..len];
    write_udp_headers(frame, header.operator, header.src_port, header.dst_port);
    let _ = report_auth::seal_report(
        header.key,
        header.epoch,
        header.seq,
        body,
        &mut frame[UDP_PAYLOAD_OFFSET..],
    );
    frame
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
