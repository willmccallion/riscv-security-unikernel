//! The rule tables: run-time DPI patterns, the signature trie and the
//! port firewall, and how each says it is full.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use sec_core::security::dpi::{AhoCorasick, DynamicRules, Pattern, PatternError, RulesFull};
use sec_core::security::firewall::{FirewallError, FirewallState};

/// `DynamicRules::add` used to return `()` and silently drop on
/// overflow, so an operator who hit the 8-pattern cap saw no error
/// and believed their pattern was loaded. The fix returns a Result
/// that the mgmt ack reports; this test pins the new
/// signalling so a future "make it return () again" refactor fails
/// loudly.
fn pattern(bytes: &[u8]) -> Pattern {
    Pattern::new(bytes).expect("a valid pattern")
}

#[test]
fn dynamic_rules_overflow_is_signalled() {
    let mut rules = DynamicRules::new();
    for i in 0..8 {
        let pat = [b'a' + i as u8; 4];
        assert!(
            rules.add(pattern(&pat)).is_ok(),
            "first 8 patterns must fit"
        );
    }
    let result = rules.add(pattern(b"ninth"));
    assert_eq!(result, Err(RulesFull));
    assert_eq!(Pattern::new(&[0u8; 33]), Err(PatternError::TooLong));
}

/// `DynamicRules::add` had no dedup, so an authenticated attacker
/// could send `AddDpiPattern(X)` 8 times and fill every slot with
/// duplicates of the same signature, wedging the 8-slot table
/// against further legitimate patterns. The fix treats a duplicate
/// add as a no-op so one logical pattern consumes one slot.
#[test]
fn dynamic_rules_dedups_duplicate_patterns() {
    let mut rules = DynamicRules::new();
    for _ in 0..8 {
        assert_eq!(rules.add(pattern(b"EICAR")), Ok(()));
    }
    // One slot consumed by EICAR — 7 more distinct patterns still fit.
    for i in 0..7u8 {
        let pat = [b'a' + i; 4];
        assert_eq!(
            rules.add(pattern(&pat)),
            Ok(()),
            "distinct pattern {i} must still fit after duplicates"
        );
    }
    assert_eq!(rules.add(pattern(b"overflow")), Err(RulesFull));
    assert!(rules.check(b"xxEICARxx"));
}

#[test]
fn dynamic_rules_remove_deletes_only_that_pattern() {
    let mut rules = DynamicRules::new();
    rules.add(pattern(b"alpha")).unwrap();
    rules.add(pattern(b"beta")).unwrap();
    rules.add(pattern(b"gamma")).unwrap();

    rules.remove(&pattern(b"beta"));

    assert!(rules.check(b"xx alpha xx") && !rules.check(b"xx beta xx") && rules.check(b"gamma"));
}

/// An empty pattern cannot exist. The check path calls
/// `payload.windows(pat.len())`, and `slice::windows(0)` is defined to
/// panic, so a stored zero-length pattern would turn the next data-plane
/// packet into a kernel panic; the mgmt dispatcher takes `len` from an
/// attacker-controlled byte.
#[test]
fn an_empty_pattern_is_refused() {
    assert_eq!(Pattern::new(&[]), Err(PatternError::Empty));
}

/// `AhoCorasick::insert` accepts patterns until the trie is full and
/// then silently drops them. Operators have no way to learn that a
/// rule did not actually take effect; the API needs to surface that.
#[test]
fn ahocorasick_signals_when_a_pattern_failed_to_insert() {
    let mut ac = AhoCorasick::new();
    for prefix in 0u8..6 {
        let mut p = Vec::with_capacity(32);
        for j in 0u8..32 {
            p.push(prefix.wrapping_add(j).wrapping_add(1));
        }
        let _ = ac.insert(&p);
    }

    let needle = b"NEEDLE_THAT_SHOULD_FAIL_TO_INSERT";
    let result = ac.insert(needle);
    assert!(
        result.is_err(),
        "trie was meant to be full; insert(needle) should have returned Err but returned Ok"
    );
}

/// `FirewallState::block_port` used to return `()` and had no dedup,
/// so an authenticated attacker could send `BlockPort(P)` 16 times
/// and permanently wedge the table against further legitimate blocks
/// — overflow was silent and duplicates consumed all 16 slots. The
/// fix dedups and returns a Result that the mgmt ack reports.
#[test]
fn firewall_dedups_and_signals_overflow() {
    let mut fw = FirewallState::new();
    // Same port 16 times must only consume one slot.
    for _ in 0..16 {
        assert_eq!(fw.block_port(9000), Ok(()));
    }
    // A different port still fits — dedup worked.
    assert_eq!(fw.block_port(9001), Ok(()));
    assert!(fw.is_blocked(9000));
    assert!(fw.is_blocked(9001));

    // Fill the remaining 14 slots with distinct ports, then confirm
    // the next distinct port overflows visibly.
    for p in 0..14u16 {
        assert_eq!(fw.block_port(10_000 + p), Ok(()));
    }
    assert_eq!(fw.block_port(30_000), Err(FirewallError::Full));
    // An already-blocked port still returns Ok even when full.
    assert_eq!(fw.block_port(9000), Ok(()));
}

#[test]
fn firewall_unblock_removes_only_that_port() {
    let mut fw = FirewallState::new();
    for port in [22, 23, 80] {
        fw.block_port(port).unwrap();
    }

    fw.unblock_port(23);

    assert!(fw.is_blocked(22) && !fw.is_blocked(23) && fw.is_blocked(80));
}

#[test]
fn firewall_unblock_frees_a_slot_in_a_full_table() {
    let mut fw = FirewallState::new();
    for port in 0..16 {
        fw.block_port(port).unwrap();
    }

    fw.unblock_port(5);

    assert_eq!(fw.block_port(100), Ok(()));
}
