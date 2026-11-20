//! Builds the signed report frames the engine sends to the operator.
//!
//! Every report (alert, mgmt ack or telemetry) is a UDP datagram whose
//! payload is a [`report_auth`](crate::security::report_auth) envelope.
//! Alerts carry a fixed-size metadata record and never echo inbound
//! payload bytes, so the mgmt network is not a relay for attacker data.

use core::net::Ipv4Addr;

use crate::config::{IP_ADDR, MAC_ADDR};
use crate::net::constants::{BROADCAST_MAC, EthernetType, IpProtocol, ethernet, ipv4, udp};
use crate::net::stack::checksum;
use crate::security::hash::ReportKey;
use crate::security::mgmt_auth::OperatorAddr;
use crate::security::report_auth::{self, telemetry_packet};

/// IPv4 broadcast fallback used before the operator address is learned.
const BROADCAST_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 100, 255);

const UDP_OFFSET: usize = ipv4::HEADER_OFFSET + ipv4::MIN_HEADER_SIZE;
const UDP_PAYLOAD_OFFSET: usize = UDP_OFFSET + udp::HEADER_SIZE;

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
    pub key: &'a ReportKey,
    /// Boot epoch.
    pub epoch: u32,
    /// Position in this boot's report stream.
    pub seq: u64,
}

/// Writes `body` as a signed report frame into `buf` and returns the
/// frame, or `None` if the body is too long to seal into `buf`, so an
/// unsigned frame can never go out.
pub fn report_frame<'a>(
    buf: &'a mut [u8; MAX_REPORT_FRAME_LEN],
    header: &ReportHeader<'_>,
    body: &[u8],
) -> Option<&'a [u8]> {
    let sealed_len = report_auth::seal_report(
        header.key,
        header.epoch,
        header.seq,
        body,
        &mut buf[UDP_PAYLOAD_OFFSET..],
    )?;
    let frame = &mut buf[..UDP_PAYLOAD_OFFSET + sealed_len];
    write_udp_headers(frame, header.operator, header.src_port, header.dst_port);
    Some(frame)
}

/// Fills the Ethernet, IPv4 and UDP headers for a frame that spans all of
/// `frame`, addressed to the operator or, before one is known, broadcast.
fn write_udp_headers(
    frame: &mut [u8],
    operator: Option<OperatorAddr>,
    src_port: u16,
    dst_port: u16,
) {
    let (dst_mac, dst_ip) = operator.map_or((BROADCAST_MAC, BROADCAST_IP), |op| (op.mac, op.ip));
    let ip_len = (frame.len() - ipv4::HEADER_OFFSET) as u16;
    let udp_len = (frame.len() - UDP_OFFSET) as u16;

    frame[..ethernet::MAC_ADDR_SIZE].copy_from_slice(&dst_mac);
    frame[ethernet::SRC_MAC_OFFSET..][..ethernet::MAC_ADDR_SIZE].copy_from_slice(&MAC_ADDR);
    frame[ethernet::TYPE_OFFSET..][..ethernet::TYPE_SIZE]
        .copy_from_slice(&(EthernetType::Ipv4 as u16).to_be_bytes());
    frame[ipv4::HEADER_OFFSET..UDP_OFFSET].copy_from_slice(&ipv4_header(dst_ip, ip_len));
    frame[UDP_OFFSET..UDP_PAYLOAD_OFFSET].copy_from_slice(&udp_header(src_port, dst_port, udp_len));
}

/// The header of an unfragmented UDP datagram of `total_len` bytes from
/// this host to `dst`, checksummed.
fn ipv4_header(dst: Ipv4Addr, total_len: u16) -> [u8; ipv4::MIN_HEADER_SIZE] {
    use ipv4::field;
    let mut header = [0u8; ipv4::MIN_HEADER_SIZE];
    header[field::VERSION_IHL] = ipv4::VERSION;
    header[field::TOTAL_LEN..][..2].copy_from_slice(&total_len.to_be_bytes());
    header[field::FLAGS_FRAGMENT..][..2].copy_from_slice(&ipv4::DONT_FRAGMENT.to_be_bytes());
    header[field::TTL] = ipv4::DEFAULT_TTL;
    header[field::PROTOCOL] = IpProtocol::Udp as u8;
    header[field::SRC..][..ipv4::IP_ADDR_SIZE].copy_from_slice(&IP_ADDR.octets());
    header[field::DST..][..ipv4::IP_ADDR_SIZE].copy_from_slice(&dst.octets());
    let csum = checksum(&header);
    header[field::CHECKSUM..][..2].copy_from_slice(&csum.to_be_bytes());
    header
}

/// A UDP header for a datagram of `len` bytes, with no checksum.
fn udp_header(src_port: u16, dst_port: u16, len: u16) -> [u8; udp::HEADER_SIZE] {
    let mut header = [0u8; udp::HEADER_SIZE];
    header[udp::SRC_PORT_OFFSET..][..2].copy_from_slice(&src_port.to_be_bytes());
    header[udp::DST_PORT_OFFSET..][..2].copy_from_slice(&dst_port.to_be_bytes());
    header[udp::LENGTH_OFFSET..][..2].copy_from_slice(&len.to_be_bytes());
    header
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::hash::MgmtKey;
    use crate::security::report_auth::ReportVerifier;

    const KEY: ReportKey = ReportKey::derive(&MgmtKey::new([7; 16]));

    fn header() -> ReportHeader<'static> {
        ReportHeader {
            operator: None,
            src_port: 1,
            dst_port: 2,
            key: &KEY,
            epoch: 3,
            seq: 4,
        }
    }

    #[test]
    fn a_report_frame_carries_its_body_sealed() {
        let mut buf = [0u8; MAX_REPORT_FRAME_LEN];

        let frame = report_frame(&mut buf, &header(), b"body").expect("fits");

        let report = ReportVerifier::new(KEY)
            .verify(&frame[UDP_PAYLOAD_OFFSET..])
            .expect("verifies");
        assert_eq!(report.body, b"body");
    }

    #[test]
    fn a_body_too_long_to_seal_yields_no_frame() {
        let mut buf = [0u8; MAX_REPORT_FRAME_LEN];
        let too_long = [0u8; MAX_REPORT_FRAME_LEN];

        assert!(report_frame(&mut buf, &header(), &too_long).is_none());
    }
}
