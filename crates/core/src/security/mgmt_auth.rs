//! Authenticated mgmt-plane wire format.
//!
//! Every UDP packet to the management port carries:
//!
//! ```text
//!   [counter: u64 BE][body: N bytes][mac: u64 BE]
//! ```
//!
//! The kernel rejects any packet whose MAC does not match
//! `SipHash-2-4(key, counter || body)` or whose counter is not valid
//! for the current boot epoch. The 64-bit counter is split into:
//!
//! ```text
//!   high 32 bits = boot epoch (set at kernel init from per-boot entropy)
//!   low  32 bits = monotonic sequence within that epoch
//! ```
//!
//! A receiver only accepts a packet if the epoch matches its own and
//! the sequence is strictly greater than the last accepted sequence.
//! This blocks three attacks:
//!
//! - **Forgery.** Without the pre-shared key an off-path attacker
//!   cannot construct a valid MAC, so they cannot ban arbitrary IPs,
//!   block ports, install BPF programs, or push DPI signatures.
//! - **In-boot replay.** A passively recorded mgmt packet cannot be
//!   re-sent within the same boot, because its sequence is now stale.
//! - **Cross-reboot replay.** A packet captured before a reboot will
//!   not verify after the reboot, because the kernel's new epoch
//!   differs from the one embedded in the captured counter.
//!
//! 64-bit MAC + 64-bit counter keeps the per-packet overhead at 16
//! bytes — small enough to leave room for the actual command inside a
//! standard MTU.

use crate::security::hash::{ct_eq, siphash24};

/// Width of the per-packet counter prefix, in bytes.
pub const COUNTER_LEN: usize = 8;
/// Width of the per-packet MAC suffix, in bytes.
pub const MAC_LEN: usize = 8;
/// Smallest possible authenticated packet: counter + 1-byte body + MAC.
pub const MIN_PACKET_LEN: usize = COUNTER_LEN + 1 + MAC_LEN;

/// An authenticated mgmt command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified<'a> {
    /// In-epoch sequence number the sender stamped on the command.
    pub seq: u32,
    /// The command body, with counter and MAC stripped.
    pub body: &'a [u8],
}

/// Stateful verifier for the authenticated mgmt protocol.
///
/// Holds the pre-shared key, the current boot epoch (high 32 bits of
/// the wire counter), and the highest sequence value (low 32 bits)
/// accepted within that epoch. Every mgmt packet is checked against
/// all three before its body is surfaced to the dispatcher.
#[derive(Debug)]
pub struct MgmtAuth {
    key: [u8; 16],
    epoch: u32,
    last_seq: u32,
}

impl MgmtAuth {
    /// Constructs a verifier from a 16-byte pre-shared key.
    ///
    /// The kernel embeds the key at compile time via `build.rs`; the
    /// host-side GUI loads it from the same source. The epoch starts
    /// at zero — the kernel must call [`Self::set_epoch`] during init with
    /// per-boot entropy before any mgmt packet can verify, so a packet
    /// captured before a reboot can never replay against the new boot.
    pub const fn new(key: [u8; 16]) -> Self {
        Self {
            key,
            epoch: 0,
            last_seq: 0,
        }
    }

    /// Installs the per-boot epoch and resets the in-epoch sequence.
    ///
    /// The epoch is the high 32 bits of every accepted counter for the
    /// lifetime of this boot. Senders learn the current epoch via the
    /// telemetry stream and stamp it into outgoing packets; verifiers
    /// reject any packet whose epoch does not match.
    pub const fn set_epoch(&mut self, epoch: u32) {
        self.epoch = epoch;
        self.last_seq = 0;
    }

    /// Returns the current boot epoch.
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Verifies an inbound mgmt packet and returns its sequence and body.
    ///
    /// Returns `None` if the packet is too short, the counter's epoch
    /// does not match the verifier's epoch (cross-reboot replay), the
    /// sequence is not strictly greater than the last accepted one
    /// (in-epoch replay), or the MAC does not match. On success the
    /// verifier advances its in-epoch sequence so the same packet
    /// cannot be replayed.
    ///
    /// The MAC is compared in constant time so an attacker cannot
    /// learn correct prefix bytes by measuring reply latency.
    pub fn verify<'a>(&mut self, packet: &'a [u8]) -> Option<Verified<'a>> {
        if packet.len() < MIN_PACKET_LEN {
            return None;
        }

        // MAC is verified BEFORE the counter is inspected. If we
        // returned early on a stale counter, an attacker measuring
        // reply latency could distinguish "wrong key" (slow, ~100
        // cycles of SipHash) from "stale counter" (fast, no hash) for
        // any chosen counter value, which leaks whether they have
        // already rolled past our last-seen sequence. Always paying
        // the SipHash cost erases that distinguisher.
        let mac_start = packet.len() - MAC_LEN;
        let signed_region = &packet[..mac_start];
        let provided_mac = &packet[mac_start..];

        let expected = siphash24(&self.key, signed_region).to_be_bytes();
        if !ct_eq(&expected, provided_mac) {
            return None;
        }

        let counter = u64::from_be_bytes([
            packet[0], packet[1], packet[2], packet[3], packet[4], packet[5], packet[6], packet[7],
        ]);
        let epoch = (counter >> 32) as u32;
        let seq = counter as u32;
        if epoch != self.epoch || seq <= self.last_seq {
            return None;
        }

        self.last_seq = seq;
        Some(Verified {
            seq,
            body: &packet[COUNTER_LEN..mac_start],
        })
    }
}

/// Parses a mgmt key written as 32 hex characters, as in
/// `KERNEL_MGMT_KEY` and `.mgmt-key.local`.
pub fn parse_hex_key(hex: &str) -> Option<[u8; 16]> {
    let hex = hex.as_bytes();
    if hex.len() != 32 {
        return None;
    }
    let mut key = [0u8; 16];
    for (byte, pair) in key.iter_mut().zip(hex.as_chunks::<2>().0) {
        *byte = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Some(key)
}

const fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Helper for senders: stamps `body` with `counter` and an authentic
/// MAC, returning the wire-format byte length written into `out`.
///
/// Returns `None` if `out` is too small to hold the authenticated
/// packet. The kernel does not need this — it only verifies — but
/// `sec_core` exposes it so the GUI and any future Linux daemon use
/// the exact same construction.
pub fn seal(key: &[u8; 16], counter: u64, body: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = COUNTER_LEN + body.len() + MAC_LEN;
    if out.len() < total {
        return None;
    }
    out[..COUNTER_LEN].copy_from_slice(&counter.to_be_bytes());
    out[COUNTER_LEN..COUNTER_LEN + body.len()].copy_from_slice(body);
    let mac = siphash24(key, &out[..COUNTER_LEN + body.len()]).to_be_bytes();
    out[COUNTER_LEN + body.len()..total].copy_from_slice(&mac);
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_EPOCH: u32 = 0xCAFE_BABE;

    fn counter(epoch: u32, seq: u32) -> u64 {
        ((epoch as u64) << 32) | (seq as u64)
    }

    fn fixture() -> ([u8; 16], MgmtAuth) {
        let key = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        let mut auth = MgmtAuth::new(key);
        auth.set_epoch(TEST_EPOCH);
        (key, auth)
    }

    #[test]
    fn parse_hex_key_accepts_32_hex_characters_in_either_case() {
        let key = parse_hex_key("00112233445566778899AaBbCcDdEeFf");

        assert_eq!(
            key,
            Some([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF,
            ])
        );
    }

    #[test]
    fn parse_hex_key_rejects_wrong_length_or_non_hex() {
        assert_eq!(parse_hex_key("0011"), None);
        assert_eq!(parse_hex_key("0011223344556677889900aabbccddeg"), None);
    }

    #[test]
    fn verify_accepts_well_formed_packet_and_returns_body() {
        let (key, mut auth) = fixture();
        let body = [0x04, 10, 0, 0, 5];
        let mut packet = [0u8; 32];
        let n = seal(&key, counter(TEST_EPOCH, 1), &body, &mut packet).unwrap();
        let got = auth.verify(&packet[..n]).expect("valid packet");
        assert_eq!(got.body, &body);
        assert_eq!(got.seq, 1);
    }

    #[test]
    fn verify_rejects_unsigned_packet() {
        let (_, mut auth) = fixture();
        let body = [0x04, 10, 0, 0, 5];
        let mut packet = [0u8; COUNTER_LEN + 5 + MAC_LEN];
        packet[..COUNTER_LEN].copy_from_slice(&counter(TEST_EPOCH, 1).to_be_bytes());
        packet[COUNTER_LEN..COUNTER_LEN + body.len()].copy_from_slice(&body);
        // MAC region left as all-zero
        assert!(auth.verify(&packet).is_none());
    }

    #[test]
    fn verify_rejects_replayed_packet() {
        let (key, mut auth) = fixture();
        let body = [0x01, 0x00, 0x50];
        let mut packet = [0u8; 32];
        let n = seal(&key, counter(TEST_EPOCH, 7), &body, &mut packet).unwrap();
        assert!(auth.verify(&packet[..n]).is_some());
        assert!(
            auth.verify(&packet[..n]).is_none(),
            "second verify of the same packet must fail (replay)"
        );
    }

    #[test]
    fn verify_rejects_packet_signed_with_wrong_key() {
        let (_, mut auth) = fixture();
        let attacker_key = [0xAA; 16];
        let body = [0x04, 10, 0, 0, 5];
        let mut packet = [0u8; 32];
        let n = seal(&attacker_key, counter(TEST_EPOCH, 1), &body, &mut packet).unwrap();
        assert!(auth.verify(&packet[..n]).is_none());
    }

    #[test]
    fn verify_rejects_short_packet() {
        let (_, mut auth) = fixture();
        let too_short = [0u8; MIN_PACKET_LEN - 1];
        assert!(auth.verify(&too_short).is_none());
    }

    #[test]
    fn verify_rejects_counter_lower_than_last_seen() {
        let (key, mut auth) = fixture();
        let body = [0x01, 0x00, 0x50];
        let mut later = [0u8; 32];
        let n_later = seal(&key, counter(TEST_EPOCH, 100), &body, &mut later).unwrap();
        assert!(auth.verify(&later[..n_later]).is_some());

        let mut earlier = [0u8; 32];
        let n_earlier = seal(&key, counter(TEST_EPOCH, 50), &body, &mut earlier).unwrap();
        assert!(auth.verify(&earlier[..n_earlier]).is_none());
    }

    #[test]
    fn verify_rejects_packet_from_prior_boot_epoch() {
        // A packet captured under one epoch (e.g. before a reboot) must
        // not verify against a verifier that has since switched to a
        // different epoch, even if the MAC is otherwise correct and the
        // sequence number would be acceptable on its own.
        let (key, mut auth) = fixture();
        let body = [0x01, 0x00, 0x50];
        let mut packet = [0u8; 32];
        let stale_epoch = TEST_EPOCH.wrapping_sub(1);
        let n = seal(&key, counter(stale_epoch, 1), &body, &mut packet).unwrap();
        assert!(auth.verify(&packet[..n]).is_none());
    }

    #[test]
    fn set_epoch_resets_in_epoch_sequence() {
        // After a (hypothetical) epoch rotation the sequence counter
        // must restart so the next packet's seq=1 is accepted.
        let (key, mut auth) = fixture();
        let body = [0x01];
        let mut packet = [0u8; 32];
        let n = seal(&key, counter(TEST_EPOCH, 50), &body, &mut packet).unwrap();
        assert!(auth.verify(&packet[..n]).is_some());

        let new_epoch = TEST_EPOCH.wrapping_add(1);
        auth.set_epoch(new_epoch);
        let mut next = [0u8; 32];
        let n2 = seal(&key, counter(new_epoch, 1), &body, &mut next).unwrap();
        assert!(auth.verify(&next[..n2]).is_some());
    }
}
