//! Frame builders and a capturing sink shared by the engine tests.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use sec_core::config::{IP_ADDR, MAC_ADDR};
use sec_core::engine::{BootSecrets, Engine};
use sec_core::net::PacketSink;
use sec_core::net::frame::{self, Frame, Transport};
use sec_core::net::stack::{SynCookieSecret, checksum};
use sec_core::net::tcp::TcpFlags;
use sec_core::security::alert::AlertReason;
use sec_core::security::hash::{MgmtKey, ReportKey, SketchKey};
use sec_core::security::mgmt::mgmt_packet::MAX_PAYLOAD_LEN;
use sec_core::security::mgmt::{Ack, Command};
use sec_core::security::mgmt_auth::{OperatorAddr, seal, sealed_len};
use sec_core::security::report_auth::{ReportBody, ReportVerifier};
use std::net::Ipv4Addr;
use std::num::NonZeroU32;

pub const KEY: MgmtKey = MgmtKey::new(*b"engine-test-key!");
pub const EPOCH: u32 = 0x1234_5678;
pub const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
pub const PEER_IP: [u8; 4] = [192, 168, 100, 1];

/// Records every frame the engine emits.
#[derive(Default)]
pub struct CaptureSink {
    pub sent: Vec<Vec<u8>>,
}

impl PacketSink for CaptureSink {
    fn send(&mut self, frame: &[u8]) {
        self.sent.push(frame.to_vec());
    }
}

impl CaptureSink {
    /// Bodies of every report emitted, in order. Panics if any report
    /// fails verification under the test key.
    pub fn report_bodies(&self) -> Vec<Vec<u8>> {
        let mut verifier = ReportVerifier::new(ReportKey::derive(&KEY));
        self.sent
            .iter()
            .filter_map(|f| udp_payload(f))
            .map(|payload| {
                verifier
                    .verify(&payload)
                    .expect("report verifies")
                    .body
                    .to_vec()
            })
            .collect()
    }

    /// Every report emitted, in order.
    pub fn reports(&self) -> Vec<ReportBody> {
        self.report_bodies()
            .iter()
            .map(|body| ReportBody::parse(body).expect("a known report"))
            .collect()
    }

    /// Reasons of every alert emitted, in order.
    pub fn alert_reasons(&self) -> Vec<AlertReason> {
        self.reports()
            .into_iter()
            .filter_map(|report| match report {
                ReportBody::Alert(alert) => Some(alert.reason),
                _ => None,
            })
            .collect()
    }
}

/// The payload of a UDP datagram in `frame`.
fn udp_payload(frame: &[u8]) -> Option<Vec<u8>> {
    let mut frame = frame.to_vec();
    match frame::parse(&mut frame) {
        Ok(Frame::Ipv4(packet)) if matches!(packet.transport, Transport::Udp(_)) => {
            Some(packet.payload().to_vec())
        }
        _ => None,
    }
}

pub fn engine() -> Engine {
    let mut e = Engine::new(KEY);
    e.init(BootSecrets {
        syn_cookie: SynCookieSecret::new([7; 16]),
        cms_key: SketchKey::new([0; 16]),
        mgmt_epoch: NonZeroU32::new(EPOCH).unwrap(),
    });
    e
}

pub fn ipv4(src_ip: [u8; 4], protocol: u8, l4: &[u8]) -> Vec<u8> {
    let total = u16::try_from(20 + l4.len()).unwrap();
    let mut f = Vec::new();
    f.extend_from_slice(&MAC_ADDR);
    f.extend_from_slice(&PEER_MAC);
    f.extend_from_slice(&[0x08, 0x00, 0x45, 0x00]);
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0, 64, protocol, 0, 0]);
    f.extend_from_slice(&src_ip);
    f.extend_from_slice(&IP_ADDR.octets());
    let csum = checksum(&f[14..34]);
    f[24..26].copy_from_slice(&csum.to_be_bytes());
    f.extend_from_slice(l4);
    f
}

pub fn udp(src_ip: [u8; 4], src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut l4 = Vec::new();
    l4.extend_from_slice(&src_port.to_be_bytes());
    l4.extend_from_slice(&dst_port.to_be_bytes());
    l4.extend_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    l4.extend_from_slice(&[0, 0]);
    l4.extend_from_slice(payload);
    ipv4(src_ip, 17, &l4)
}

pub fn tcp(src_ip: [u8; 4], src_port: u16, dst_port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    tcp_segment(
        src_ip,
        (src_port, dst_port),
        TcpFlags::new(flags),
        0,
        payload,
    )
}

/// A TCP segment between `ports` (source, destination) with sequence
/// number `seq`.
pub fn tcp_segment(
    src_ip: [u8; 4],
    (src_port, dst_port): (u16, u16),
    flags: TcpFlags,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut l4 = vec![0u8; 20];
    l4[0..2].copy_from_slice(&src_port.to_be_bytes());
    l4[2..4].copy_from_slice(&dst_port.to_be_bytes());
    l4[4..8].copy_from_slice(&seq.to_be_bytes());
    l4[12] = 0x50;
    l4[13] = flags.bits();
    l4.extend_from_slice(payload);
    ipv4(src_ip, 6, &l4)
}

/// An ARP request from the peer asking who has `target_ip`, with the
/// given hardware type (1 for Ethernet).
pub fn arp_request(hw_type: u16, target_ip: [u8; 4]) -> Vec<u8> {
    let mut f = Vec::with_capacity(42);
    f.extend_from_slice(&[0xFF; 6]);
    f.extend_from_slice(&PEER_MAC);
    f.extend_from_slice(&[0x08, 0x06]);
    f.extend_from_slice(&hw_type.to_be_bytes());
    f.extend_from_slice(&[0x08, 0x00, 6, 4, 0x00, 0x01]);
    f.extend_from_slice(&PEER_MAC);
    f.extend_from_slice(&PEER_IP);
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&target_ip);
    f
}

/// An ICMP echo request with a correct checksum carrying `data`.
pub fn icmp_echo_with_payload(src_ip: [u8; 4], data: &[u8]) -> Vec<u8> {
    let mut l4 = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
    l4.extend_from_slice(data);
    let csum = checksum(&l4);
    l4[2..4].copy_from_slice(&csum.to_be_bytes());
    ipv4(src_ip, 1, &l4)
}

pub fn icmp_echo(src_ip: [u8; 4], checksum_field: u16) -> Vec<u8> {
    let mut l4 = vec![8, 0];
    l4.extend_from_slice(&checksum_field.to_be_bytes());
    l4.extend_from_slice(&[0, 1, 0, 1]);
    l4.extend_from_slice(&[0xAB; 32]);
    ipv4(src_ip, 1, &l4)
}

/// The wire body of `command`.
pub fn body(command: &Command) -> Vec<u8> {
    let mut out = [0u8; MAX_PAYLOAD_LEN];
    command.encode(&mut out).to_vec()
}

/// A UDP frame to the mgmt port carrying `body` sealed under `seq`.
pub fn mgmt(seq: u32, body: &[u8]) -> Vec<u8> {
    let counter = (u64::from(EPOCH) << 32) | u64::from(seq);
    let operator = OperatorAddr {
        mac: PEER_MAC,
        ip: Ipv4Addr::from(PEER_IP),
    };
    let mut sealed = vec![0u8; sealed_len(body.len())];
    let n = seal(&KEY, counter, &operator, body, &mut sealed).unwrap();
    udp(
        PEER_IP,
        40_000,
        sec_core::config::MANAGEMENT_PORT,
        &sealed[..n],
    )
}

/// Every mgmt ack emitted, in order.
pub fn acks(sink: &CaptureSink) -> Vec<Ack> {
    sink.reports()
        .into_iter()
        .filter_map(|report| match report {
            ReportBody::Ack(ack) => Some(ack),
            _ => None,
        })
        .collect()
}
