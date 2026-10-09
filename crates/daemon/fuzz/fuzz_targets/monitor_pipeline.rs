//! Any sequence of frames, of any link types and timings, runs through the
//! whole monitor (decoding, flows, hosts, names, reassembly and summaries)
//! without panicking, and summaries stay consistent.

#![no_main]

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use security_daemon::monitor::decode::LinkType;
use security_daemon::monitor::net::LocalNetworks;
use security_daemon::monitor::pipeline::{Monitor, Summary};
use security_daemon::monitor::time::UnixNanos;
use std::time::Duration;

#[derive(Debug, Arbitrary)]
struct Frame {
    link: u8,
    gap_micros: u32,
    extra_wire_len: u16,
    bytes: Vec<u8>,
}

fn check(summary: &Summary) {
    let listed: u64 = summary.hosts.iter().map(|h| h.activity.sent.packets).sum();
    assert!(listed <= summary.totals.ip().packets, "hosts sent more than was seen");
}

fuzz_target!(|frames: Vec<Frame>| {
    let local = LocalNetworks::new(vec!["10.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()]);
    let mut monitor = Monitor::new(local, Duration::from_secs(1));
    let mut now = 1_700_000_000_000_000_000u64;
    for frame in frames {
        now += u64::from(frame.gap_micros) * 1_000;
        let link = match frame.link % 4 {
            0 => LinkType::Ethernet,
            1 => LinkType::RawIp,
            2 => LinkType::LinuxSll,
            _ => LinkType::LinuxSll2,
        };
        let wire_len = u32::try_from(frame.bytes.len()).unwrap_or(u32::MAX).saturating_add(u32::from(frame.extra_wire_len));
        if let Some(summary) = monitor.observe(link, &frame.bytes, wire_len, UnixNanos::new(now)) {
            check(&summary);
        }
    }
    if let Some(summary) = monitor.finish() {
        check(&summary);
    }
});
