//! Capturing from a live interface.

use super::net::{IpPrefix, LocalNetworks};
use super::pipeline::{Monitor, Summary};
use super::report;
use super::time::UnixNanos;
use crate::af_packet::{Outgoing, RxRing};
use crate::{netif, privileges};
use anyhow::Result;
use std::time::{Duration, Instant};

/// Captures on `interface`, receive-only and without privileges once the
/// socket is open, printing a summary every second.
pub fn run(interface: &str, duration: Option<Duration>, extra_local_networks: &[IpPrefix]) -> Result<()> {
    let mut ring = RxRing::open(interface, Outgoing::Include)?;
    privileges::drop_all()?;
    let mut prefixes = netif::interface_networks(interface)?;
    prefixes.extend_from_slice(extra_local_networks);
    let mut monitor = Monitor::new(ring.link_type(), LocalNetworks::new(prefixes), report::INTERVAL);
    println!("monitor: capturing on {interface} ({:?}), receive-only, no privileges", ring.link_type());
    report::print_local_networks(monitor.local_networks());

    let started = Instant::now();
    while duration.is_none_or(|d| started.elapsed() < d) {
        let mut closed: Vec<Summary> = Vec::new();
        let _ = ring.poll(100, |frame| {
            closed.extend(monitor.observe(frame.data, frame.wire_len, UnixNanos::new(frame.captured_at_unix_ns)));
        })?;
        closed.extend(monitor.tick(UnixNanos::now()));
        if !closed.is_empty() {
            let drops = ring.stats()?.drops;
            for summary in &closed {
                report::print_summary(summary);
            }
            if drops > 0 {
                println!("monitor: the capture ring dropped {drops} frames; the summaries above undercount");
            }
        }
    }
    Ok(())
}
