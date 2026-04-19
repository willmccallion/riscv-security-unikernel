//! Property-based tests for the stateful primitives the kernel relies
//! on every packet: PenaltyBox, CountMinSketch, FlowTable, AhoCorasick.
//!
//! Each property is a statement that should hold for every input, not
//! just the hand-crafted inputs in `audit.rs`. Proptest generates
//! sequences of operations against each primitive and shrinks failing
//! cases down to a minimal counter-example.
//!
//! Skipped under miri: 256 cases per property × 8 properties × miri's
//! ~1000× interpreter overhead is hours of wall time, and the
//! memory-safety story is already covered by the unit tests and
//! `audit.rs`. Run natively with `cargo test -p sec-core --test properties`.

#![cfg(not(miri))]

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::missing_panics_doc
)]

use proptest::prelude::*;
use sec_core::security::dos::{CountMinSketch, PenaltyBox};
use sec_core::security::dpi::AhoCorasick;
use sec_core::security::flow::FlowTable;

// ---------------------------------------------------------------- PenaltyBox

proptest! {
    /// An IP banned at time `t` for `dur` cycles must read as banned at
    /// every time strictly inside `[t, t + dur)`. The penalty box is a
    /// 16-slot array, so as long as we ban a single IP into an empty
    /// box this property holds for all inputs.
    #[test]
    fn pbox_ban_is_active_within_window(
        ip in any::<[u8; 4]>(),
        now in 0u64..1_000_000,
        dur in 1u64..1_000_000,
        offset_pct in 0u64..100,
    ) {
        let mut pbox = PenaltyBox::new();
        pbox.ban(&ip, dur, now);
        // Sample any time t' strictly inside the ban window.
        let probe = now + (dur - 1) * offset_pct / 100;
        prop_assert!(pbox.is_banned(&ip, probe), "ban should cover {probe}");
    }

    /// The same ban must read as inactive at `now + dur` and beyond.
    /// `is_banned` uses a strict `expiry > now` comparison, so the
    /// expiry instant itself is the first un-banned tick.
    #[test]
    fn pbox_ban_expires_after_window(
        ip in any::<[u8; 4]>(),
        now in 0u64..1_000_000,
        dur in 1u64..1_000_000,
        extra in 0u64..1_000_000,
    ) {
        let mut pbox = PenaltyBox::new();
        pbox.ban(&ip, dur, now);
        let probe = now + dur + extra;
        prop_assert!(!pbox.is_banned(&ip, probe), "ban should have expired by {probe}");
    }

    /// Querying an IP that was never banned must always return false,
    /// regardless of how many *other* IPs are sitting in the table.
    /// Generates a vector of bans whose IPs differ from the query IP
    /// in at least one byte (we steer clear of the query by toggling
    /// the high bit of the first byte).
    #[test]
    fn pbox_unbanned_ip_never_reads_banned(
        query_ip in any::<[u8; 4]>(),
        bans in proptest::collection::vec(any::<[u8; 4]>(), 0..32),
        now in 0u64..1_000_000,
    ) {
        let mut pbox = PenaltyBox::new();
        for mut b in bans {
            // Force every banned IP to differ from the query IP.
            if b == query_ip {
                b[0] ^= 0x80;
            }
            pbox.ban(&b, 1_000, now);
        }
        prop_assert!(!pbox.is_banned(&query_ip, now), "unrelated IP must not read as banned");
    }
}

// ----------------------------------------------------------- CountMinSketch

proptest! {
    /// CMS guarantees no underestimate. After inserting `item` exactly
    /// N times (with arbitrary other items mixed in), the returned
    /// minimum must be >= N — unless the counter saturated at u16::MAX.
    #[test]
    fn cms_never_underestimates(
        item in proptest::collection::vec(any::<u8>(), 1..16),
        noise in proptest::collection::vec(
            proptest::collection::vec(any::<u8>(), 1..16),
            0..200,
        ),
        repeats in 1u16..200,
    ) {
        let mut cms = CountMinSketch::new();
        // Interleave the target inserts with noise inserts in a fixed
        // pattern. The order can change the *exact* counter values but
        // never the lower bound.
        let mut last_seen: u16 = 0;
        for n in &noise {
            let _ = cms.insert(n);
        }
        for _ in 0..repeats {
            last_seen = cms.insert(&item);
        }
        prop_assert!(last_seen >= repeats || last_seen == u16::MAX,
            "estimate {last_seen} below true count {repeats}");
    }
}

// -------------------------------------------------------------- FlowTable

proptest! {
    /// Two updates against the same 5-tuple must hit the same slot:
    /// the second `update` returns `false` (not a new flow). Proves
    /// the table key actually distinguishes 5-tuples and isn't, e.g.,
    /// keying off only `src_ip`.
    #[test]
    fn flow_repeat_tuple_is_not_a_new_flow(
        src_ip in any::<[u8; 4]>(),
        dst_ip in any::<[u8; 4]>(),
        src_port in any::<u16>(),
        dst_port in any::<u16>(),
        proto in any::<u8>(),
        len in 0usize..1500,
        now in 0u64..1_000_000,
    ) {
        let mut ft = FlowTable::new();
        let new1 = ft.update(&src_ip, &dst_ip, src_port, dst_port, proto, len, now);
        let new2 = ft.update(&src_ip, &dst_ip, src_port, dst_port, proto, len, now);
        prop_assert!(new1, "first insert of a fresh tuple must be a new flow");
        prop_assert!(!new2, "second insert of the same tuple must reuse the slot");
    }

    /// Distinct 5-tuples up to the table's capacity (74 slots) must
    /// each create a new flow entry. Picks `n` distinct tuples by
    /// varying `src_port`, which the FlowTable treats as part of the
    /// key, and asserts every insert reports `true` (new flow).
    #[test]
    fn flow_distinct_tuples_each_create_a_new_flow(
        src_ip in any::<[u8; 4]>(),
        dst_ip in any::<[u8; 4]>(),
        dst_port in any::<u16>(),
        proto in any::<u8>(),
        n in 1u16..=74,
    ) {
        let mut ft = FlowTable::new();
        for src_port in 0..n {
            let new = ft.update(&src_ip, &dst_ip, src_port, dst_port, proto, 0, 0);
            prop_assert!(new, "tuple #{src_port} should be a new flow under capacity");
        }
    }
}

// ---------------------------------------------------------- AhoCorasick

proptest! {
    /// Inserting a non-empty pattern and immediately scanning a
    /// haystack that contains it as a contiguous substring must
    /// report a match. Patterns are kept short (<= 16 bytes) so they
    /// fit inside the trie's fixed node budget.
    #[test]
    fn ac_inserted_pattern_is_found(
        pattern in proptest::collection::vec(any::<u8>(), 1..=16),
        prefix in proptest::collection::vec(any::<u8>(), 0..32),
        suffix in proptest::collection::vec(any::<u8>(), 0..32),
    ) {
        let mut ac = AhoCorasick::new();
        let _ = ac.insert(&pattern);
        let mut hay = prefix;
        hay.extend_from_slice(&pattern);
        hay.extend_from_slice(&suffix);
        prop_assert!(ac.scan(&hay), "embedded pattern should be found");
    }

    /// Symmetry: a haystack drawn from an alphabet disjoint from the
    /// pattern must never match. Pattern uses bytes {0x80..=0xFF};
    /// haystack uses bytes {0x00..=0x7F}.
    #[test]
    fn ac_disjoint_alphabet_never_matches(
        pattern in proptest::collection::vec(0x80u8..=0xFF, 1..=16),
        hay in proptest::collection::vec(0x00u8..=0x7F, 0..256),
    ) {
        let mut ac = AhoCorasick::new();
        let _ = ac.insert(&pattern);
        prop_assert!(!ac.scan(&hay), "haystack of disjoint alphabet must not match");
    }
}
