//! Replaying a pcap capture file through the monitor.

use super::net::{IpPrefix, LocalNetworks};
use super::pcap::PcapReader;
use super::pipeline::Monitor;
use super::report;
use crate::privileges;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

/// Replays `path` as fast as it can be read, using the file's timestamps,
/// and prints a summary for every second of capture time.
pub fn run(path: &Path, local_networks: &[IpPrefix]) -> Result<()> {
    privileges::drop_all()?;
    let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = PcapReader::new(BufReader::new(file)).with_context(|| format!("in {}", path.display()))?;
    if local_networks.is_empty() {
        println!("monitor: no local networks given (--local-network); all unicast traffic will count as transit");
    }
    let link = reader.link_type();
    let mut monitor = Monitor::new(LocalNetworks::new(local_networks.to_vec()), report::INTERVAL);
    report::print_local_networks(monitor.local_networks());

    let mut frame = Vec::new();
    while let Some(record) = reader.next_record(&mut frame).with_context(|| format!("in {}", path.display()))? {
        if let Some(summary) = monitor.observe(link, &frame, record.wire_len, record.at) {
            report::print_summary(&summary);
        }
    }
    if let Some(summary) = monitor.finish() {
        report::print_summary(&summary);
    }
    Ok(())
}
