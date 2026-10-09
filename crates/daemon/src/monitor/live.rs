//! Capturing from live interfaces.

use super::net::{IpPrefix, LocalNetworks};
use super::pipeline::{Monitor, Summary};
use super::report;
use super::time::UnixNanos;
use crate::af_packet::{self, Outgoing, RxRing};
use crate::{netif, privileges};
use anyhow::Result;
use std::time::{Duration, Instant};

/// How long to wait for frames when every interface is quiet.
const IDLE_WAIT_MS: i32 = 100;

/// Captures on every interface in `interfaces`, receive-only and without
/// privileges once the sockets are open, printing a summary every second.
/// The interfaces' own networks, and `extra_local_networks`, are local.
pub fn run(interfaces: &[String], duration: Option<Duration>, extra_local_networks: &[IpPrefix]) -> Result<()> {
    let mut rings = interfaces
        .iter()
        .map(|name| RxRing::open(name, Outgoing::Include))
        .collect::<Result<Vec<_>>>()?;
    privileges::drop_all()?;
    let mut prefixes = Vec::new();
    for name in interfaces {
        prefixes.extend(netif::interface_networks(name)?);
    }
    prefixes.extend_from_slice(extra_local_networks);
    let mut monitor = Monitor::new(LocalNetworks::new(prefixes), report::INTERVAL);
    for (name, ring) in interfaces.iter().zip(&rings) {
        println!("monitor: capturing on {name} ({:?}), receive-only, no privileges", ring.link_type());
    }
    report::print_local_networks(monitor.local_networks());

    let started = Instant::now();
    while duration.is_none_or(|d| started.elapsed() < d) {
        let mut closed: Vec<Summary> = Vec::new();
        let mut seen = 0;
        for ring in &mut rings {
            let link = ring.link_type();
            seen += ring.poll(0, |frame| {
                let at = UnixNanos::new(frame.captured_at_unix_ns);
                closed.extend(monitor.observe(link, frame.data, frame.wire_len, at));
            })?;
        }
        if seen == 0 {
            af_packet::wait_for_any(&rings, IDLE_WAIT_MS)?;
        }
        closed.extend(monitor.tick(UnixNanos::now()));
        if !closed.is_empty() {
            report_closed(&closed, interfaces, &rings)?;
        }
    }
    Ok(())
}

fn report_closed(closed: &[Summary], interfaces: &[String], rings: &[RxRing]) -> Result<()> {
    for summary in closed {
        report::print_summary(summary);
    }
    for (name, ring) in interfaces.iter().zip(rings) {
        let drops = ring.stats()?.drops;
        if drops > 0 {
            println!("monitor: capture on {name} dropped {drops} frames; the summaries above undercount");
        }
    }
    Ok(())
}
