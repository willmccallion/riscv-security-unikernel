//! The penalty box: how bans are kept, renewed and evicted when full.

use sec_core::security::dos::{PenaltyBox, PenaltyBoxFull};
use sec_core::time::{TickSpan, Ticks};
use std::net::Ipv4Addr;

/// `PenaltyBox::ban` used to allocate a fresh slot even when the IP
/// was already banned, so an authenticated attacker sending
/// `BanIp(X)` 16 times with the same X filled every slot with
/// duplicates. The fix refreshes the existing entry in place so
/// duplicates consume one slot regardless of how many times they
/// arrive.
#[test]
fn penalty_box_dedups_duplicate_bans() {
    let mut pbox = PenaltyBox::new();
    let now = 1_000u64;
    let dur = 10_000u64;
    let target = Ipv4Addr::new(10, 0, 0, 1);

    for _ in 0..16 {
        pbox.ban(target, TickSpan::new(dur), Ticks::new(now));
    }
    assert!(pbox.is_banned(target, Ticks::new(now)));

    // With dedup, 15 slots are still free — 15 further distinct bans
    // must all land without evicting `target`.
    for i in 2..17u8 {
        pbox.ban(
            Ipv4Addr::new(10, 0, 0, i),
            TickSpan::new(dur),
            Ticks::new(now),
        );
    }
    assert!(
        pbox.is_banned(target, Ticks::new(now)),
        "duplicate-ban dedup must not have evicted the first IP"
    );
    for i in 2..17u8 {
        assert!(pbox.is_banned(Ipv4Addr::new(10, 0, 0, i), Ticks::new(now)));
    }
}

/// Once the penalty box is full, every additional `ban` call must not
/// land in the same slot deterministically — otherwise an attacker can
/// predict which IPs survive eviction and force the same one to keep
/// flipping out.
#[test]
fn penalty_box_does_not_clobber_a_single_slot_when_full() {
    let mut pbox = PenaltyBox::new();
    let now = 1_000u64;
    let dur = 100_000u64;

    for i in 0..16u8 {
        let ip = Ipv4Addr::new(10, 0, 0, i);
        pbox.ban(ip, TickSpan::new(dur), Ticks::new(now));
        assert!(pbox.is_banned(ip, Ticks::new(now)));
    }

    let first = Ipv4Addr::new(10, 0, 0, 0);
    assert!(pbox.is_banned(first, Ticks::new(now)));

    for i in 16..20u8 {
        let ip = Ipv4Addr::new(10, 0, 0, i);
        pbox.ban(ip, TickSpan::new(dur), Ticks::new(now));
    }

    let surviving = (16..20u8)
        .filter(|i| pbox.is_banned(Ipv4Addr::new(10, 0, 0, *i), Ticks::new(now)))
        .count();

    assert!(
        surviving >= 2,
        "after 4 overflow bans only {surviving}/4 are still banned; one slot is always overwritten"
    );
}

#[test]
fn penalty_box_ban_near_the_end_of_time_does_not_overflow() {
    let mut pbox = PenaltyBox::new();

    pbox.ban(
        Ipv4Addr::new(10, 0, 0, 1),
        TickSpan::new(u64::MAX),
        Ticks::new(u64::MAX - 5),
    );

    assert!(pbox.is_banned(Ipv4Addr::new(10, 0, 0, 1), Ticks::new(u64::MAX - 1)));
}

/// Detector bans rotate through the full table, but must never push out
/// a ban the operator chose.
#[test]
fn penalty_box_detector_bans_never_evict_an_operator_ban() {
    let mut pbox = PenaltyBox::new();
    pbox.ban_by_operator(
        Ipv4Addr::new(10, 9, 9, 9),
        TickSpan::new(1_000),
        Ticks::new(0),
    )
    .unwrap();

    for i in 0..32u8 {
        pbox.ban(
            Ipv4Addr::new(20, 0, 0, i),
            TickSpan::new(1_000),
            Ticks::new(0),
        );
    }

    assert!(pbox.is_banned(Ipv4Addr::new(10, 9, 9, 9), Ticks::new(1)));
}

#[test]
fn penalty_box_operator_ban_evicts_a_detector_ban_when_full() {
    let mut pbox = PenaltyBox::new();
    for i in 0..16u8 {
        pbox.ban(
            Ipv4Addr::new(20, 0, 0, i),
            TickSpan::new(1_000),
            Ticks::new(0),
        );
    }

    let result = pbox.ban_by_operator(
        Ipv4Addr::new(10, 9, 9, 9),
        TickSpan::new(1_000),
        Ticks::new(0),
    );

    assert_eq!(result, Ok(()));
    assert!(pbox.is_banned(Ipv4Addr::new(10, 9, 9, 9), Ticks::new(1)));
}

#[test]
fn penalty_box_refuses_an_operator_ban_when_every_slot_holds_one() {
    let mut pbox = PenaltyBox::new();
    for i in 0..16u8 {
        pbox.ban_by_operator(
            Ipv4Addr::new(10, 0, 0, i),
            TickSpan::new(1_000),
            Ticks::new(0),
        )
        .unwrap();
    }

    let result = pbox.ban_by_operator(
        Ipv4Addr::new(10, 0, 1, 1),
        TickSpan::new(1_000),
        Ticks::new(0),
    );

    assert_eq!(result, Err(PenaltyBoxFull));
    assert!((0..16u8).all(|i| pbox.is_banned(Ipv4Addr::new(10, 0, 0, i), Ticks::new(1))));
}

/// A detector re-banning an address the operator banned must not shorten
/// the operator's ban or make it evictable.
#[test]
fn penalty_box_detector_reban_keeps_the_operator_ban() {
    let mut pbox = PenaltyBox::new();
    pbox.ban_by_operator(
        Ipv4Addr::new(10, 9, 9, 9),
        TickSpan::new(10_000),
        Ticks::new(0),
    )
    .unwrap();
    pbox.ban(
        Ipv4Addr::new(10, 9, 9, 9),
        TickSpan::new(100),
        Ticks::new(0),
    );

    for i in 0..32u8 {
        pbox.ban(
            Ipv4Addr::new(20, 0, 0, i),
            TickSpan::new(1_000),
            Ticks::new(200),
        );
    }

    assert!(pbox.is_banned(Ipv4Addr::new(10, 9, 9, 9), Ticks::new(5_000)));
}

#[test]
fn penalty_box_reuses_a_ban_ending_now_before_evicting_an_active_one() {
    let mut pbox = PenaltyBox::new();
    for i in 0..15u8 {
        pbox.ban(
            Ipv4Addr::new(10, 0, 0, i),
            TickSpan::new(1_000),
            Ticks::new(0),
        );
    }
    pbox.ban(
        Ipv4Addr::new(10, 0, 0, 15),
        TickSpan::new(100),
        Ticks::new(0),
    );

    pbox.ban(
        Ipv4Addr::new(10, 0, 1, 1),
        TickSpan::new(100),
        Ticks::new(100),
    );

    assert!(
        pbox.is_banned(Ipv4Addr::new(10, 0, 0, 0), Ticks::new(100)),
        "an active ban was evicted"
    );
}
