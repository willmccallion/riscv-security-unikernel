//! Authenticated wire format for kernel-to-operator reports.
//!
//! Telemetry, alerts and mgmt acks travel as:
//!
//! ```text
//!   [epoch: u32 BE][seq: u64 BE][body: N bytes][mac: u64 BE]
//! ```
//!
//! where `mac = SipHash-2-4(report_key, epoch || seq || body)`. The report
//! key is derived from the mgmt key under a fixed label, so a report can
//! never be replayed to the kernel as a command, and the 64-bit sequence
//! cannot wrap under any realistic alert rate.

use crate::security::alert::{Alert, alert_packet};
use crate::security::hash::{ReportKey, ct_eq};
use crate::security::mgmt::{Ack, ack_packet};

/// Bytes before the body: epoch and sequence.
pub const HEADER_LEN: usize = 4 + 8;
/// Bytes after the body: the MAC.
pub const MAC_LEN: usize = 8;
/// Envelope overhead added to every report body.
pub const OVERHEAD: usize = HEADER_LEN + MAC_LEN;

/// Layout of the telemetry report body.
pub mod telemetry_packet {
    /// Message-type byte distinguishing telemetry from alerts and acks.
    pub const MESSAGE_TYPE: u8 = 0x01;
    /// Number of big-endian u64 counters after the type byte.
    pub const SLOTS: usize = 11;
    /// Offset of the first counter.
    pub const SLOTS_OFFSET: usize = 1;
    /// Total bytes of telemetry body.
    pub const BODY_LEN: usize = SLOTS_OFFSET + SLOTS * 8;
}

/// One telemetry interval's counters, in their order on the wire.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Telemetry {
    /// User packets that cleared every check.
    pub passed: u64,
    /// Drops from the penalty box, heavy-hitter sketch or rate limiter.
    pub ddos: u64,
    /// Drops from the port firewall.
    pub firewall: u64,
    /// DPI signature matches.
    pub malware: u64,
    /// Drops by the installed BPF program.
    pub bpf: u64,
    /// Heuristic anomalies.
    pub heuristic: u64,
    /// Bytes of RAM the kernel uses.
    pub memory_used: u64,
    /// Flows being tracked.
    pub active_flows: u64,
    /// Mgmt-plane packets, authenticated or not.
    pub mgmt: u64,
    /// The boot epoch.
    pub epoch: u32,
    /// The last mgmt sequence accepted this boot.
    pub last_mgmt_seq: u32,
}

impl Telemetry {
    /// The report body carrying these counters.
    pub fn encode(&self) -> [u8; telemetry_packet::BODY_LEN] {
        let slots = [
            self.passed,
            self.ddos,
            self.firewall,
            self.malware,
            self.bpf,
            self.heuristic,
            self.memory_used,
            self.active_flows,
            self.mgmt,
            u64::from(self.epoch),
            u64::from(self.last_mgmt_seq),
        ];
        let mut body = [0u8; telemetry_packet::BODY_LEN];
        body[0] = telemetry_packet::MESSAGE_TYPE;
        let (chunks, _) = body[telemetry_packet::SLOTS_OFFSET..].as_chunks_mut::<8>();
        for (chunk, slot) in chunks.iter_mut().zip(slots) {
            chunk.copy_from_slice(&slot.to_be_bytes());
        }
        body
    }

    /// The counters in a report body, if it is a whole telemetry report
    /// whose epoch and sequence fit in 32 bits.
    pub fn decode(body: &[u8]) -> Option<Self> {
        let body = body.first_chunk::<{ telemetry_packet::BODY_LEN }>()?;
        if body[0] != telemetry_packet::MESSAGE_TYPE {
            return None;
        }
        let (chunks, _) = body[telemetry_packet::SLOTS_OFFSET..].as_chunks::<8>();
        let mut slots = [0u64; telemetry_packet::SLOTS];
        for (slot, chunk) in slots.iter_mut().zip(chunks) {
            *slot = u64::from_be_bytes(*chunk);
        }
        let [
            passed,
            ddos,
            firewall,
            malware,
            bpf,
            heuristic,
            memory_used,
            active_flows,
            mgmt,
            epoch,
            last_mgmt_seq,
        ] = slots;
        Some(Self {
            passed,
            ddos,
            firewall,
            malware,
            bpf,
            heuristic,
            memory_used,
            active_flows,
            mgmt,
            epoch: u32::try_from(epoch).ok()?,
            last_mgmt_seq: u32::try_from(last_mgmt_seq).ok()?,
        })
    }
}

/// What a report carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportBody {
    /// One interval's counters.
    Telemetry(Telemetry),
    /// A security alert.
    Alert(Alert),
    /// The answer to a mgmt command.
    Ack(Ack),
}

impl ReportBody {
    /// The report in `body`, or `None` for an unknown type or a body
    /// its type's decoder refuses.
    pub fn parse(body: &[u8]) -> Option<Self> {
        match *body.first()? {
            telemetry_packet::MESSAGE_TYPE => Telemetry::decode(body).map(Self::Telemetry),
            alert_packet::ALERT_MESSAGE_TYPE => Alert::decode(body).map(Self::Alert),
            ack_packet::ACK_MESSAGE_TYPE => Ack::decode(body).map(Self::Ack),
            _ => None,
        }
    }
}

/// Epochs a verifier remembers so replays from earlier boots stay rejected.
const REMEMBERED_EPOCHS: usize = 8;

/// Writes `body` into `out` as a sealed report and returns its length, or
/// `None` if `out` is too small.
pub fn seal_report(
    key: &ReportKey,
    epoch: u32,
    seq: u64,
    body: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let signed_len = HEADER_LEN + body.len();
    let out = out.get_mut(..signed_len + MAC_LEN)?;
    out[..4].copy_from_slice(&epoch.to_be_bytes());
    out[4..HEADER_LEN].copy_from_slice(&seq.to_be_bytes());
    out[HEADER_LEN..signed_len].copy_from_slice(body);
    let mac = key.hash(&out[..signed_len]);
    out[signed_len..].copy_from_slice(&mac.to_be_bytes());
    Some(out.len())
}

/// A verified report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report<'a> {
    /// Boot epoch of the kernel that sent it.
    pub epoch: u32,
    /// Position in that boot's report stream.
    pub seq: u64,
    /// The report body.
    pub body: &'a [u8],
}

/// Receiver-side verifier for one kernel's reports.
///
/// Accepts a report only if its MAC is valid and, within the current boot,
/// its sequence is higher than any accepted before. A report from a new
/// epoch is taken as a reboot only if that epoch has not been seen before,
/// so frames recorded from an earlier boot cannot be replayed to drag the
/// receiver back to a stale epoch.
#[derive(Debug)]
pub struct ReportVerifier {
    key: ReportKey,
    current: Option<(u32, u64)>,
    retired: [Option<u32>; REMEMBERED_EPOCHS],
    next_retired: usize,
}

impl ReportVerifier {
    /// Creates a verifier for reports sealed under `report_key`.
    pub const fn new(report_key: ReportKey) -> Self {
        Self {
            key: report_key,
            current: None,
            retired: [None; REMEMBERED_EPOCHS],
            next_retired: 0,
        }
    }

    /// The epoch of the most recently accepted report, if any.
    pub fn epoch(&self) -> Option<u32> {
        self.current.map(|(epoch, _)| epoch)
    }

    /// Verifies `packet` and returns its contents, or `None` if it is
    /// forged, malformed, replayed or from a retired epoch.
    pub fn verify<'a>(&mut self, packet: &'a [u8]) -> Option<Report<'a>> {
        let signed_len = packet.len().checked_sub(MAC_LEN)?;
        if signed_len < HEADER_LEN {
            return None;
        }
        let expected = self.key.hash(&packet[..signed_len]).to_be_bytes();
        if !ct_eq(&expected, &packet[signed_len..]) {
            return None;
        }
        let epoch = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&packet[4..HEADER_LEN]);
        let seq = u64::from_be_bytes(seq);

        match self.current {
            Some((current, last)) if current == epoch && seq <= last => return None,
            Some((current, _)) if current != epoch => {
                if self.retired.contains(&Some(epoch)) {
                    return None;
                }
                self.retired[self.next_retired] = Some(current);
                self.next_retired = (self.next_retired + 1) % REMEMBERED_EPOCHS;
            }
            _ => {}
        }
        self.current = Some((epoch, seq));
        Some(Report {
            epoch,
            seq,
            body: &packet[HEADER_LEN..signed_len],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::alert::{AlertMeta, AlertReason};
    use crate::security::hash::MgmtKey;
    use crate::security::mgmt::MgmtOutcome;
    use core::net::Ipv4Addr;

    const TELEMETRY: Telemetry = Telemetry {
        passed: 1,
        ddos: 2,
        firewall: 3,
        malware: 4,
        bpf: 5,
        heuristic: 6,
        memory_used: 7,
        active_flows: 8,
        mgmt: 9,
        epoch: 10,
        last_mgmt_seq: 11,
    };

    const ALERT: Alert = Alert {
        reason: AlertReason::SubnetFlood,
        meta: AlertMeta {
            src_ip: Ipv4Addr::new(10, 1, 2, 0),
            dst_ip: Ipv4Addr::new(192, 168, 100, 2),
            src_port: 1234,
            dst_port: 80,
            protocol: 17,
            packet_len: 512,
            prefix_len: 24,
            value: 4200,
        },
    };

    const ACK: Ack = Ack {
        seq: 0xDEAD_BEEF,
        command: 0xEE,
        outcome: MgmtOutcome::Refused,
    };

    #[test]
    fn telemetry_counters_sit_in_wire_order() {
        let body = TELEMETRY.encode();

        for (slot, expected) in body[telemetry_packet::SLOTS_OFFSET..].chunks(8).zip(1u64..) {
            assert_eq!(slot, expected.to_be_bytes());
        }
    }

    #[test]
    fn each_report_body_parses_back_to_what_was_encoded() {
        assert_eq!(
            ReportBody::parse(&TELEMETRY.encode()),
            Some(ReportBody::Telemetry(TELEMETRY))
        );
        assert_eq!(
            ReportBody::parse(&ALERT.encode()),
            Some(ReportBody::Alert(ALERT))
        );
        assert_eq!(ReportBody::parse(&ACK.encode()), Some(ReportBody::Ack(ACK)));
    }

    #[test]
    fn a_truncated_body_of_each_type_is_refused() {
        let telemetry = TELEMETRY.encode();
        let alert = ALERT.encode();
        let ack = ACK.encode();

        assert_eq!(ReportBody::parse(&telemetry[..telemetry.len() - 1]), None);
        assert_eq!(ReportBody::parse(&alert[..alert.len() - 1]), None);
        assert_eq!(ReportBody::parse(&ack[..ack.len() - 1]), None);
    }

    #[test]
    fn unknown_types_reasons_and_outcomes_are_refused() {
        let mut alert = ALERT.encode();
        alert[alert_packet::REASON_OFFSET] = 0xFF;
        let mut ack = ACK.encode();
        ack[ack_packet::OUTCOME_OFFSET] = 0xFF;

        assert_eq!(ReportBody::parse(&[]), None);
        assert_eq!(ReportBody::parse(&[0xEE; 32]), None);
        assert_eq!(ReportBody::parse(&alert), None);
        assert_eq!(ReportBody::parse(&ack), None);
    }

    #[test]
    fn telemetry_whose_epoch_overflows_32_bits_is_refused() {
        let mut body = TELEMETRY.encode();
        let epoch_slot = telemetry_packet::SLOTS_OFFSET + 9 * 8;
        body[epoch_slot..epoch_slot + 8].copy_from_slice(&(1u64 << 32).to_be_bytes());

        assert_eq!(Telemetry::decode(&body), None);
    }

    const KEY: ReportKey = ReportKey::derive(&MgmtKey::new([7; 16]));

    fn sealed(epoch: u32, seq: u64, body: &[u8]) -> ([u8; 64], usize) {
        let mut out = [0u8; 64];
        let n = seal_report(&KEY, epoch, seq, body, &mut out).unwrap();
        (out, n)
    }

    #[test]
    fn accepts_a_sealed_report() {
        let mut v = ReportVerifier::new(KEY);
        let (packet, n) = sealed(5, 1, b"hello");

        let report = v.verify(&packet[..n]).unwrap();

        assert_eq!(
            (report.epoch, report.seq, report.body),
            (5, 1, &b"hello"[..])
        );
    }

    #[test]
    fn rejects_a_tampered_report() {
        let mut v = ReportVerifier::new(KEY);
        let (mut packet, n) = sealed(5, 1, b"hello");
        packet[HEADER_LEN] ^= 1;

        assert!(v.verify(&packet[..n]).is_none());
    }

    #[test]
    fn rejects_replays_within_a_boot() {
        let mut v = ReportVerifier::new(KEY);
        let (packet, n) = sealed(5, 9, b"x");
        assert!(v.verify(&packet[..n]).is_some());

        assert!(v.verify(&packet[..n]).is_none());
    }

    #[test]
    fn follows_a_reboot_but_not_a_replay_from_the_previous_boot() {
        let mut v = ReportVerifier::new(KEY);
        let (old, n_old) = sealed(5, 9, b"old boot");
        let (new, n_new) = sealed(6, 1, b"new boot");
        assert!(v.verify(&old[..n_old]).is_some());
        assert!(v.verify(&new[..n_new]).is_some());

        let (older, n_older) = sealed(5, 10, b"old boot");

        assert!(v.verify(&older[..n_older]).is_none());
        assert_eq!(v.epoch(), Some(6));
    }
}
