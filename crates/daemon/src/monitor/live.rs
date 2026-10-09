//! Capturing from live interfaces.

use super::command::{MonitorOptions, Serving};
use super::link::{self, ViewerServer};
use super::net::LocalNetworks;
use super::pipeline::{Monitor, Summary};
use super::report::{self, Detail};
use super::time::UnixNanos;
use crate::af_packet::{self, Outgoing, RxRing};
use crate::{netif, privileges};
use crate::sandbox::WriteAccess;
use anyhow::{Context, Result};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

/// How long to wait for frames when every interface is quiet.
const IDLE_WAIT_MS: i32 = 100;

/// Captures on every interface in `interfaces`, printing a summary every
/// second and, if `options` say so, streaming it to viewers.
///
/// Capture is receive-only, and once the sockets are open the process
/// drops its privileges and is confined as `options` say, still able to
/// write to viewers but never to a capture socket. The interfaces' own
/// networks, and the extra ones in `options`, are local.
pub fn run(interfaces: &[String], duration: Option<Duration>, options: &MonitorOptions) -> Result<()> {
    let mut rings = interfaces
        .iter()
        .map(|name| RxRing::open(name, Outgoing::Include))
        .collect::<Result<Vec<_>>>()?;
    privileges::drop_all()?;
    let mut prefixes = Vec::new();
    for name in interfaces {
        prefixes.extend(netif::interface_networks(name)?);
    }
    prefixes.extend_from_slice(&options.extra_local_networks);
    let local = LocalNetworks::new(prefixes);
    let mut viewers = start_serving(&options.serving, interfaces, &local)?;
    let mut monitor = Monitor::new(local, report::INTERVAL);
    for (name, ring) in interfaces.iter().zip(&rings) {
        println!("monitor: capturing on {name} ({:?}), receive-only, no privileges", ring.link_type());
    }
    report::print_local_networks(monitor.local_networks());
    options.sandboxing.apply(write_access(&rings, viewers.is_some())?)?;

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
        if let Some(viewers) = &mut viewers {
            viewers.accept_viewers()?;
            for summary in &closed {
                viewers.send(summary)?;
            }
        }
        if !closed.is_empty() {
            report_closed(&closed, interfaces, &rings, options.detail)?;
        }
    }
    Ok(())
}

/// Opens the viewers' socket if serving, and says where to find it.
fn start_serving(serving: &Serving, interfaces: &[String], local: &LocalNetworks) -> Result<Option<ViewerServer>> {
    let Some(path) = serving.path()? else { return Ok(None) };
    let interval_ms = u64::try_from(report::INTERVAL.as_millis()).unwrap_or(u64::MAX);
    let server = ViewerServer::bind(&path, &link::hello(interfaces, local, interval_ms))?;
    println!("monitor: serving viewers at {}", path.display());
    println!(
        "monitor: from another machine: ssh -L /tmp/security-monitor.sock:{} <this host>",
        path.display()
    );
    Ok(Some(server))
}

/// What the confined process may write to: stdout and stderr, plus,
/// when serving, every descriptor above the capture sockets, which is
/// where viewers' connections will land.
fn write_access(rings: &[RxRing], serving: bool) -> Result<WriteAccess> {
    if !serving {
        return Ok(WriteAccess::StdioOnly);
    }
    let highest_capture_fd = rings.iter().map(AsRawFd::as_raw_fd).max().unwrap_or(2);
    let fds_from = u32::try_from(highest_capture_fd).context("capture descriptor out of range")? + 1;
    Ok(WriteAccess::StdioAndViewers { fds_from })
}

fn report_closed(closed: &[Summary], interfaces: &[String], rings: &[RxRing], detail: Detail) -> Result<()> {
    for summary in closed {
        report::print_summary(summary, detail);
    }
    for (name, ring) in interfaces.iter().zip(rings) {
        let drops = ring.stats()?.drops;
        if drops > 0 {
            println!("monitor: capture on {name} dropped {drops} frames; the summaries above undercount");
        }
    }
    Ok(())
}
