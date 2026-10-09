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

use crate::security::hash::{ct_eq, derive_key, siphash24};

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
    pub const SLOTS: usize = 10;
    /// Offset of the first counter.
    pub const SLOTS_OFFSET: usize = 1;
    /// Total bytes of telemetry body.
    pub const BODY_LEN: usize = SLOTS_OFFSET + SLOTS * 8;
}

/// Epochs a verifier remembers so replays from earlier boots stay rejected.
const REMEMBERED_EPOCHS: usize = 8;

/// Derives the report-signing key from the pre-shared mgmt key.
pub const fn report_key(mgmt_key: &[u8; 16]) -> [u8; 16] {
    derive_key(mgmt_key, b"sec-core report key")
}

/// Writes `body` into `out` as a sealed report and returns its length, or
/// `None` if `out` is too small.
pub fn seal_report(key: &[u8; 16], epoch: u32, seq: u64, body: &[u8], out: &mut [u8]) -> Option<usize> {
    let signed_len = HEADER_LEN + body.len();
    let out = out.get_mut(..signed_len + MAC_LEN)?;
    out[..4].copy_from_slice(&epoch.to_be_bytes());
    out[4..HEADER_LEN].copy_from_slice(&seq.to_be_bytes());
    out[HEADER_LEN..signed_len].copy_from_slice(body);
    let mac = siphash24(key, &out[..signed_len]);
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
    key: [u8; 16],
    current: Option<(u32, u64)>,
    retired: [Option<u32>; REMEMBERED_EPOCHS],
    next_retired: usize,
}

impl ReportVerifier {
    /// Creates a verifier for reports sealed under `report_key`.
    pub const fn new(report_key: [u8; 16]) -> Self {
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
        let expected = siphash24(&self.key, &packet[..signed_len]).to_be_bytes();
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

    const KEY: [u8; 16] = [7; 16];

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

        assert_eq!((report.epoch, report.seq, report.body), (5, 1, &b"hello"[..]));
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

    #[test]
    fn report_key_differs_from_the_mgmt_key() {
        assert_ne!(report_key(&KEY), KEY);
    }
}
