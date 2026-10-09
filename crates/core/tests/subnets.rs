//! Heavy-hitter detection at the subnet level: many moderate hosts in one
//! /24 or /16 add up to an attack that per-host counting cannot see.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{CaptureSink, engine, udp};
use sec_core::config::CMS_DECAY_INTERVAL_CYCLES;
use sec_core::engine::{Engine, Verdict};
use sec_core::security::alert::AlertReason;

/// Sends `seconds` of traffic: every host in `hosts` at `pps`, interleaved,
/// ending a detection interval every half second.
fn run(e: &mut Engine, sink: &mut CaptureSink, hosts: &[[u8; 4]], pps: u64, seconds: u64, now: &mut u64) {
    let interval = CMS_DECAY_INTERVAL_CYCLES as u64;
    let per_interval = pps * interval / 1_000_000_000;
    for _ in 0..seconds * 1_000_000_000 / interval {
        let packets = per_interval * hosts.len() as u64;
        let step = interval / packets.max(1);
        for k in 0..packets {
            *now += step;
            let host = hosts[(k % hosts.len() as u64) as usize];
            let _ = e.process(&mut udp(host, 5000, 80, b"x"), *now, sink);
        }
        e.end_detection_interval(sink);
    }
}

fn hosts(prefix: [u8; 3], count: u8) -> Vec<[u8; 4]> {
    (1..=count).map(|h| [prefix[0], prefix[1], prefix[2], h]).collect()
}

#[test]
fn many_moderate_hosts_get_their_slash_24_banned() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut now = 0;

    run(&mut e, &mut sink, &hosts([10, 5, 5], 20), 80, 2, &mut now);

    let newcomer = e.process(&mut udp([10, 5, 5, 200], 5000, 80, b"x"), now + 1, &mut sink);
    let neighbour = e.process(&mut udp([10, 5, 6, 1], 5000, 80, b"x"), now + 2, &mut sink);
    assert_eq!(newcomer, Verdict::Dropped(AlertReason::Ddos), "the /24 is banned");
    assert_eq!(neighbour, Verdict::Passed, "the next /24 is not");
    assert!(sink.alert_reasons().contains(&AlertReason::SubnetFlood));
}

#[test]
fn one_loud_host_is_banned_alone_not_its_subnet() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut now = 0;

    run(&mut e, &mut sink, &[[10, 7, 7, 7]], 3_000, 2, &mut now);

    let sibling = e.process(&mut udp([10, 7, 7, 8], 5000, 80, b"x"), now + 1, &mut sink);
    assert_eq!(sibling, Verdict::Passed);
    assert!(!sink.alert_reasons().contains(&AlertReason::SubnetFlood));
}

#[test]
fn moderate_slash_24s_add_up_to_a_banned_slash_16() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut now = 0;
    let all: Vec<[u8; 4]> = (0..10u8).flat_map(|net| hosts([10, 9, net], 10)).collect();

    run(&mut e, &mut sink, &all, 60, 2, &mut now);

    let elsewhere_in_16 = e.process(&mut udp([10, 9, 200, 1], 5000, 80, b"x"), now + 1, &mut sink);
    let outside = e.process(&mut udp([10, 10, 0, 1], 5000, 80, b"x"), now + 2, &mut sink);
    assert_eq!(elsewhere_in_16, Verdict::Dropped(AlertReason::Ddos), "the /16 is banned");
    assert_eq!(outside, Verdict::Passed);
}

#[test]
fn ordinary_traffic_bans_no_subnet() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut now = 0;
    let all: Vec<[u8; 4]> = (0..20u8).flat_map(|net| hosts([10, 11, net], 5)).collect();

    run(&mut e, &mut sink, &all, 20, 3, &mut now);

    assert!(!sink.alert_reasons().contains(&AlertReason::SubnetFlood));
}

#[test]
fn the_appliances_own_subnets_are_never_banned() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut now = 0;
    let own = sec_core::config::IP_ADDR;

    run(&mut e, &mut sink, &hosts([own[0], own[1], own[2]], 20), 80, 2, &mut now);

    let neighbour = e.process(&mut udp([own[0], own[1], own[2], 200], 5000, 80, b"x"), now + 1, &mut sink);
    assert_eq!(neighbour, Verdict::Passed);
    assert!(!sink.alert_reasons().contains(&AlertReason::SubnetFlood));
}

#[test]
fn other_slash_24s_inside_the_appliances_slash_16_can_still_be_banned() {
    let mut e = engine();
    let mut sink = CaptureSink::default();
    let mut now = 0;
    let own = sec_core::config::IP_ADDR;

    run(&mut e, &mut sink, &hosts([own[0], own[1], own[2].wrapping_add(1)], 20), 80, 2, &mut now);

    assert!(sink.alert_reasons().contains(&AlertReason::SubnetFlood));
}
