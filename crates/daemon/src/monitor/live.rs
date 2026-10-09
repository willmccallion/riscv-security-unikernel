//! Capturing from a live interface and reporting what crosses it.

use super::decode::{self, LinkType};
use super::net::{IpPrefix, LocalNetworks};
use super::totals::TrafficTotals;
use crate::af_packet::{CapturedFrame, Outgoing, RxRing};
use crate::{netif, privileges};
use anyhow::Result;
use std::time::{Duration, Instant};

/// How often a summary line is printed.
const SUMMARY_INTERVAL: Duration = Duration::from_secs(1);

/// What `monitor` watches and for how long.
#[derive(Debug, Clone)]
pub struct MonitorOptions {
    /// Interface to capture on.
    pub interface: String,
    /// Networks to treat as local besides the interface's own.
    pub extra_local_networks: Vec<IpPrefix>,
    /// Stop after this long; run until killed if `None`.
    pub duration: Option<Duration>,
}

/// Captures on the interface, receive-only, and prints a traffic summary
/// every second.
pub fn run(options: &MonitorOptions) -> Result<()> {
    let mut ring = RxRing::open(&options.interface, Outgoing::Include)?;
    let link = ring.link_type();
    privileges::drop_all()?;
    let local = local_networks(options)?;
    println!("monitor: capturing on {} ({link:?}), receive-only, no privileges", options.interface);
    let prefixes: Vec<String> = local.prefixes().iter().map(ToString::to_string).collect();
    println!("monitor: local networks {}", prefixes.join(", "));

    let started = Instant::now();
    let mut last_summary = started;
    let mut totals = TrafficTotals::default();
    while options.duration.is_none_or(|d| started.elapsed() < d) {
        let _ = ring.poll(100, |frame| record(&mut totals, &local, link, &frame))?;
        let elapsed = last_summary.elapsed();
        if elapsed >= SUMMARY_INTERVAL {
            let stats = ring.stats()?;
            println!("{} | ring drops {}", totals.rates(elapsed), stats.drops);
            totals = TrafficTotals::default();
            last_summary = Instant::now();
        }
    }
    Ok(())
}

fn local_networks(options: &MonitorOptions) -> Result<LocalNetworks> {
    let mut prefixes = netif::interface_networks(&options.interface)?;
    prefixes.extend(options.extra_local_networks.iter().copied());
    Ok(LocalNetworks::new(prefixes))
}

fn record(totals: &mut TrafficTotals, local: &LocalNetworks, link: LinkType, frame: &CapturedFrame<'_>) {
    match decode::decode(link, frame.data) {
        Some(packet) => totals.record(&packet, local.direction(packet.src, packet.dst), frame.wire_len),
        None => totals.record_non_ip(frame.wire_len),
    }
}
