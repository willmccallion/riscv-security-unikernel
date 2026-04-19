//! Authenticated mgmt-plane wire format.
//!
//! Every UDP packet to the management port carries:
//!
//! ```text
//!   [counter: u64 BE][body: N bytes][mac: u64 BE]
//! ```
//!
//! The kernel rejects any packet whose MAC does not match
//! `SipHash-2-4(key, counter || body)` or whose counter is not
//! strictly greater than the last accepted counter. This blocks two
//! attacks that the previous implementation was wide open to:
//!
//! - **Forgery.** Without the pre-shared key an off-path attacker
//!   cannot construct a valid MAC, so they cannot ban arbitrary IPs,
//!   block ports, install eBPF programs, or push DPI signatures.
//! - **Replay.** A passively recorded mgmt packet cannot be re-sent to
//!   re-execute the same command, because its counter is now stale.
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

/// Stateful verifier for the authenticated mgmt protocol.
///
/// Holds the pre-shared key and the highest counter value seen so far.
/// Every mgmt packet is checked against both before its body is
/// surfaced to the dispatcher.
#[derive(Debug)]
pub struct MgmtAuth {
    key: [u8; 16],
    last_counter: u64,
}

impl MgmtAuth {
    /// Constructs a verifier from a 16-byte pre-shared key.
    ///
    /// The kernel embeds the key at compile time via `build.rs`; the
    /// host-side GUI loads it from the same source. `last_counter`
    /// starts at zero — survives reboots because the counter the
    /// sender issues is monotonic for the lifetime of the receiver,
    /// and a receiver that just rebooted will accept everything from
    /// `1` upward.
    pub const fn new(key: [u8; 16]) -> Self {
        Self {
            key,
            last_counter: 0,
        }
    }

    /// Verifies an inbound mgmt packet and returns its body slice.
    ///
    /// Returns `None` if the packet is too short, the counter is not
    /// strictly greater than the last accepted counter (replay), or
    /// the MAC does not match. On success the verifier advances its
    /// last-seen counter so the same packet cannot be replayed.
    ///
    /// The MAC is compared in constant time so an attacker cannot
    /// learn correct prefix bytes by measuring reply latency.
    pub fn verify<'a>(&mut self, packet: &'a [u8]) -> Option<&'a [u8]> {
        if packet.len() < MIN_PACKET_LEN {
            return None;
        }

        let counter = u64::from_be_bytes([
            packet[0], packet[1], packet[2], packet[3], packet[4], packet[5], packet[6], packet[7],
        ]);
        if counter <= self.last_counter {
            return None;
        }

        let mac_start = packet.len() - MAC_LEN;
        let signed_region = &packet[..mac_start];
        let provided_mac = &packet[mac_start..];

        let expected = siphash24(&self.key, signed_region).to_be_bytes();
        if !ct_eq(&expected, provided_mac) {
            return None;
        }

        self.last_counter = counter;
        Some(&packet[COUNTER_LEN..mac_start])
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

    fn fixture() -> ([u8; 16], MgmtAuth) {
        let key = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ];
        (key, MgmtAuth::new(key))
    }

    #[test]
    fn verify_accepts_well_formed_packet_and_returns_body() {
        let (key, mut auth) = fixture();
        let body = [0x04, 10, 0, 0, 5];
        let mut packet = [0u8; 32];
        let n = seal(&key, 1, &body, &mut packet).unwrap();
        let got = auth.verify(&packet[..n]).expect("valid packet");
        assert_eq!(got, &body);
    }

    #[test]
    fn verify_rejects_unsigned_packet() {
        let (_, mut auth) = fixture();
        let body = [0x04, 10, 0, 0, 5];
        let mut packet = [0u8; COUNTER_LEN + 5 + MAC_LEN];
        packet[..COUNTER_LEN].copy_from_slice(&1u64.to_be_bytes());
        packet[COUNTER_LEN..COUNTER_LEN + body.len()].copy_from_slice(&body);
        // MAC region left as all-zero
        assert!(auth.verify(&packet).is_none());
    }

    #[test]
    fn verify_rejects_replayed_packet() {
        let (key, mut auth) = fixture();
        let body = [0x01, 0x00, 0x50];
        let mut packet = [0u8; 32];
        let n = seal(&key, 7, &body, &mut packet).unwrap();
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
        let n = seal(&attacker_key, 1, &body, &mut packet).unwrap();
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
        let n_later = seal(&key, 100, &body, &mut later).unwrap();
        assert!(auth.verify(&later[..n_later]).is_some());

        let mut earlier = [0u8; 32];
        let n_earlier = seal(&key, 50, &body, &mut earlier).unwrap();
        assert!(auth.verify(&earlier[..n_earlier]).is_none());
    }
}
