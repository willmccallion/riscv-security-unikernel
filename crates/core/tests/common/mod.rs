//! Frame builders and a capturing sink shared by the engine tests.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use sec_core::config::{IP_ADDR, MAC_ADDR};
use sec_core::engine::{BootSecrets, Engine};
use sec_core::net::PacketSink;
use sec_core::net::stack::{SynCookieSecret, checksum};
use sec_core::security::alert::{AlertReason, alert_packet};
use sec_core::security::mgmt_auth::seal;
use sec_core::security::report_auth::{ReportVerifier, report_key};

pub const KEY: [u8; 16] = *b"engine-test-key!";
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
        let mut verifier = ReportVerifier::new(report_key(&KEY));
        self.sent
            .iter()
            .filter(|f| f.len() > 42 && f[23] == 17)
            .map(|f| {
                let report = verifier.verify(&f[42..]).expect("report verifies");
                report.body.to_vec()
            })
            .collect()
    }

    /// Reasons of every alert emitted, in order.
    pub fn alert_reasons(&self) -> Vec<AlertReason> {
        self.report_bodies()
            .iter()
            .filter(|body| body[0] == alert_packet::ALERT_MESSAGE_TYPE)
            .map(|body| AlertReason::from_u8(body[alert_packet::REASON_OFFSET]).expect("known reason"))
            .collect()
    }
}

pub fn engine() -> Engine {
    let mut e = Engine::new(KEY);
    e.init(BootSecrets {
        syn_cookie: SynCookieSecret::new([7; 16]),
        cms_key: [0; 16],
        mgmt_epoch: EPOCH,
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
    f.extend_from_slice(&IP_ADDR);
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
    let mut l4 = vec![0u8; 20];
    l4[0..2].copy_from_slice(&src_port.to_be_bytes());
    l4[2..4].copy_from_slice(&dst_port.to_be_bytes());
    l4[12] = 0x50;
    l4[13] = flags;
    l4.extend_from_slice(payload);
    ipv4(src_ip, 6, &l4)
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

/// A UDP frame to the mgmt port carrying `body` sealed under `seq`.
pub fn mgmt(seq: u32, body: &[u8]) -> Vec<u8> {
    let counter = (u64::from(EPOCH) << 32) | u64::from(seq);
    let mut sealed = vec![0u8; 16 + body.len()];
    let n = seal(&KEY, counter, body, &mut sealed).unwrap();
    udp(PEER_IP, 40_000, sec_core::config::MANAGEMENT_PORT, &sealed[..n])
}

/// `(seq, command, outcome)` of every mgmt ack emitted, in order.
pub fn acks(sink: &CaptureSink) -> Vec<(u32, u8, u8)> {
    use sec_core::security::mgmt::ack_packet::{
        ACK_MESSAGE_TYPE, COMMAND_OFFSET, OUTCOME_OFFSET, SEQ_OFFSET,
    };
    sink.report_bodies()
        .into_iter()
        .filter(|body| body[0] == ACK_MESSAGE_TYPE)
        .map(|body| {
            let seq = u32::from_be_bytes(body[SEQ_OFFSET..SEQ_OFFSET + 4].try_into().unwrap());
            (seq, body[COMMAND_OFFSET], body[OUTCOME_OFFSET])
        })
        .collect()
}
