//! Printing the monitor's findings to the terminal.

use super::hosts::Locality;
use super::net::LocalNetworks;
use super::pipeline::{Diagnostics, Summary};
use super::totals::SiBits;
use super::time::UnixNanos;
use std::fmt;
use std::time::Duration;

/// How often traffic is summarised.
pub const INTERVAL: Duration = Duration::from_secs(1);

/// Prints which networks count as local.
pub fn print_local_networks(local: &LocalNetworks) {
    let prefixes: Vec<String> = local.prefixes().iter().map(ToString::to_string).collect();
    println!("monitor: local networks {}", prefixes.join(", "));
}

/// Remote hosts named in each summary line.
const TOP_REMOTE_HOSTS: usize = 3;

/// How much each summary shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Detail {
    /// Traffic and the busiest remote hosts.
    #[default]
    Normal,
    /// Also what could not be decoded and how naming went.
    Verbose,
}

/// Prints one interval's summary, stamped with its start in UTC, and the
/// busiest remote hosts; with [`Detail::Verbose`], diagnostics too.
pub fn print_summary(summary: &Summary, detail: Detail) {
    println!("{} {}", UtcClock(summary.start), summary.totals.rates(summary.length));
    let seconds = summary.length.as_secs_f64().max(1e-9);
    let top: Vec<String> = summary
        .hosts
        .iter()
        .filter(|h| h.activity.locality == Locality::Remote)
        .take(TOP_REMOTE_HOSTS)
        .map(|h| {
            let label = h.name.as_ref().map_or_else(|| h.activity.addr.to_string(), |n| n.name.to_string());
            format!(
                "{label} \u{2193}{}/s \u{2191}{}/s",
                SiBits(h.activity.sent.bytes as f64 * 8.0 / seconds),
                SiBits(h.activity.received.bytes as f64 * 8.0 / seconds)
            )
        })
        .collect();
    if !top.is_empty() {
        println!(
            "          top: {} | {} flows{}",
            top.join(", "),
            summary.active_flows,
            if summary.untracked > 0 { format!(", {} packets untracked", summary.untracked) } else { String::new() }
        );
    }
    if detail == Detail::Verbose {
        println!("          diag: {}", DiagnosticsLine(&summary.diagnostics));
    }
}

/// [`Diagnostics`] on one line.
struct DiagnosticsLine<'a>(&'a Diagnostics);

impl fmt::Display for DiagnosticsLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let d = self.0;
        let not_ip: Vec<String> = d.not_ip.iter().map(|(why, count)| format!("{why} {count}")).collect();
        write!(
            f,
            "non-IP [{}] | dns {} mdns {} | tls hellos {} named {} | quic initials {} named {}",
            not_ip.join(", "),
            d.dns_responses,
            d.mdns_responses,
            d.tls_hellos_seen,
            d.tls_names,
            d.quic_initials,
            d.quic_names
        )
    }
}

/// The time of day of a moment, in UTC, as `HH:MM:SSZ`.
struct UtcClock(UnixNanos);

impl fmt::Display for UtcClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let seconds_of_day = self.0.as_nanos() / 1_000_000_000 % 86_400;
        write!(
            f,
            "{:02}:{:02}:{:02}Z",
            seconds_of_day / 3600,
            seconds_of_day / 60 % 60,
            seconds_of_day % 60
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_clock_shows_the_time_of_day() {
        let moment = UnixNanos::new((86_400 * 3 + 13 * 3600 + 7 * 60 + 9) * 1_000_000_000 + 5);

        assert_eq!(UtcClock(moment).to_string(), "13:07:09Z");
    }
}
