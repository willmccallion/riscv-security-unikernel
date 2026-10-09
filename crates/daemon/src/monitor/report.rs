//! Printing the monitor's findings to the terminal.

use super::net::LocalNetworks;
use super::pipeline::Summary;
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

/// Prints one interval's summary, stamped with its start in UTC.
pub fn print_summary(summary: &Summary) {
    println!("{} {}", UtcClock(summary.start), summary.totals.rates(summary.length));
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
