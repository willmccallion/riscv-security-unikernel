//! What the live network view knows: recent summaries from the monitor,
//! and the per-host totals and throughput history drawn from them.

use monitor_proto::{Hello, Host, HostName, Locality, Summary};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;

/// Seconds of history kept for charts and windows.
pub const HISTORY_SECONDS: u64 = 10 * 60;

/// A span of recent time to total hosts' traffic over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Window {
    /// The last ten seconds.
    #[default]
    TenSeconds,
    /// The last minute.
    OneMinute,
    /// The last ten minutes.
    TenMinutes,
}

impl Window {
    /// Every window, shortest first.
    pub const ALL: [Self; 3] = [Self::TenSeconds, Self::OneMinute, Self::TenMinutes];

    /// The window's length in seconds.
    pub const fn seconds(self) -> u64 {
        match self {
            Self::TenSeconds => 10,
            Self::OneMinute => 60,
            Self::TenMinutes => 600,
        }
    }

    /// A short label for a selector.
    pub const fn label(self) -> &'static str {
        match self {
            Self::TenSeconds => "10 s",
            Self::OneMinute => "1 min",
            Self::TenMinutes => "10 min",
        }
    }
}

/// Bits per second in each direction at one moment.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Throughput {
    /// Seconds since the Unix epoch.
    pub at_secs: f64,
    /// From the internet to local addresses.
    pub inbound_bps: f64,
    /// From local addresses to the internet.
    pub outbound_bps: f64,
    /// Within the local networks.
    pub local_bps: f64,
}

/// One host's traffic totalled over a [`Window`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRow {
    /// Its address.
    pub addr: IpAddr,
    /// Its best known name.
    pub name: Option<HostName>,
    /// Bytes it sent.
    pub sent_bytes: u64,
    /// Bytes it received.
    pub received_bytes: u64,
    /// Flows it started.
    pub flows_opened: u64,
    /// Flows others started with it.
    pub flows_accepted: u64,
}

impl HostRow {
    /// Bytes in both directions.
    pub const fn total_bytes(&self) -> u64 {
        self.sent_bytes + self.received_bytes
    }
}

/// The monitor's stream, as the view needs it.
#[derive(Debug, Default)]
pub struct LiveNetwork {
    hello: Option<Hello>,
    history: VecDeque<Summary>,
    names: HashMap<IpAddr, HostName>,
}

impl LiveNetwork {
    /// Takes in the monitor's greeting on a new connection.
    pub fn connected(&mut self, hello: Hello) {
        self.hello = Some(hello);
    }

    /// What the monitor said it watches, if connected since startup.
    pub const fn hello(&self) -> Option<&Hello> {
        self.hello.as_ref()
    }

    /// Takes in one interval's summary, keeping [`HISTORY_SECONDS`] of
    /// them and remembering every name seen.
    pub fn add(&mut self, summary: Summary) {
        for host in &summary.hosts {
            if let Some(name) = &host.name {
                let _ = self.names.insert(host.addr, name.clone());
            }
        }
        self.history.push_back(summary);
        let newest = self.history.back().map_or(0, |s| s.start_unix_ms);
        while self
            .history
            .front()
            .is_some_and(|oldest| newest.saturating_sub(oldest.start_unix_ms) >= HISTORY_SECONDS * 1000)
        {
            let _ = self.history.pop_front();
        }
    }

    /// The newest summary.
    pub fn latest(&self) -> Option<&Summary> {
        self.history.back()
    }

    /// The best name known for `addr`.
    pub fn name(&self, addr: IpAddr) -> Option<&HostName> {
        self.names.get(&addr)
    }

    /// Throughput second by second over the kept history, with seconds
    /// the monitor saw no traffic in shown as zero.
    pub fn throughput(&self) -> Vec<Throughput> {
        let mut points = Vec::with_capacity(self.history.len());
        let mut previous_ms: Option<u64> = None;
        for summary in &self.history {
            let length_ms = summary.length_ms.max(1);
            if let Some(previous) = previous_ms {
                let mut quiet = previous + length_ms;
                while quiet < summary.start_unix_ms {
                    points.push(Throughput {
                        at_secs: quiet as f64 / 1000.0,
                        inbound_bps: 0.0,
                        outbound_bps: 0.0,
                        local_bps: 0.0,
                    });
                    quiet += length_ms;
                }
            }
            let bps = |bytes: u64| bytes as f64 * 8.0 * 1000.0 / length_ms as f64;
            points.push(Throughput {
                at_secs: summary.start_unix_ms as f64 / 1000.0,
                inbound_bps: bps(summary.totals.inbound.bytes),
                outbound_bps: bps(summary.totals.outbound.bytes),
                local_bps: bps(summary.totals.internal.bytes),
            });
            previous_ms = Some(summary.start_unix_ms);
        }
        points
    }

    /// Hosts of `locality` that were active in `window`, busiest first.
    pub fn hosts(&self, window: Window, locality: Locality) -> Vec<HostRow> {
        let mut rows: HashMap<IpAddr, HostRow> = HashMap::new();
        for host in self.hosts_in(window).filter(|h| h.locality == locality) {
            let row = rows.entry(host.addr).or_insert_with(|| HostRow {
                addr: host.addr,
                name: None,
                sent_bytes: 0,
                received_bytes: 0,
                flows_opened: 0,
                flows_accepted: 0,
            });
            row.sent_bytes += host.sent.bytes;
            row.received_bytes += host.received.bytes;
            row.flows_opened += u64::from(host.flows_opened);
            row.flows_accepted += u64::from(host.flows_accepted);
        }
        let mut rows: Vec<HostRow> = rows
            .into_values()
            .map(|row| HostRow {
                name: self.names.get(&row.addr).cloned(),
                ..row
            })
            .collect();
        rows.sort_by(|a, b| b.total_bytes().cmp(&a.total_bytes()).then(a.addr.cmp(&b.addr)));
        rows
    }

    /// `addr`'s bytes per second, in and out, over the kept history, as
    /// `(seconds since the epoch, bytes it sent, bytes it received)`.
    pub fn host_history(&self, addr: IpAddr) -> Vec<(f64, u64, u64)> {
        self.history
            .iter()
            .map(|summary| {
                let host = summary.hosts.iter().find(|h| h.addr == addr);
                (
                    summary.start_unix_ms as f64 / 1000.0,
                    host.map_or(0, |h| h.sent.bytes),
                    host.map_or(0, |h| h.received.bytes),
                )
            })
            .collect()
    }

    fn hosts_in(&self, window: Window) -> impl Iterator<Item = &Host> {
        let newest = self.history.back().map_or(0, |s| s.start_unix_ms);
        self.history
            .iter()
            .filter(move |s| newest.saturating_sub(s.start_unix_ms) < window.seconds() * 1000)
            .flat_map(|s| s.hosts.iter())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use monitor_proto::{Counter, NameSource, Totals};

    fn host(addr: &str, locality: Locality, sent: u64, received: u64, name: Option<&str>) -> Host {
        Host {
            addr: addr.parse().unwrap(),
            locality,
            name: name.map(|name| HostName {
                name: name.into(),
                source: NameSource::TlsServerName,
            }),
            sent: Counter { packets: 1, bytes: sent },
            received: Counter { packets: 1, bytes: received },
            flows_opened: 0,
            flows_accepted: 1,
        }
    }

    fn summary(second: u64, inbound_bytes: u64, hosts: Vec<Host>) -> Summary {
        Summary {
            start_unix_ms: second * 1000,
            length_ms: 1000,
            totals: Totals {
                inbound: Counter { packets: 1, bytes: inbound_bytes },
                ..Totals::default()
            },
            hosts,
            hosts_omitted: 0,
            active_flows: 1,
            untracked: 0,
        }
    }

    #[test]
    fn hosts_are_totalled_over_the_window_busiest_first() {
        let mut live = LiveNetwork::default();
        live.add(summary(100, 0, vec![host("1.1.1.1", Locality::Remote, 100, 10, None)]));
        live.add(summary(105, 0, vec![host("1.1.1.1", Locality::Remote, 100, 10, None), host("8.8.8.8", Locality::Remote, 500, 0, None)]));
        live.add(summary(115, 0, vec![host("1.1.1.1", Locality::Remote, 100, 10, None)]));

        let last_ten = live.hosts(Window::TenSeconds, Locality::Remote);
        let last_minute = live.hosts(Window::OneMinute, Locality::Remote);

        assert_eq!(last_ten.len(), 1, "the 8.8.8.8 second fell out of the 10 s window");
        assert_eq!(last_minute[0].addr.to_string(), "8.8.8.8");
        assert_eq!(last_minute[1].sent_bytes, 300);
        assert_eq!(last_minute[1].flows_accepted, 3);
    }

    #[test]
    fn names_are_remembered_after_later_summaries_omit_them() {
        let mut live = LiveNetwork::default();
        live.add(summary(1, 0, vec![host("2606:4700::1", Locality::Remote, 1, 1, Some("www.cloudflare.com"))]));
        live.add(summary(2, 0, vec![host("2606:4700::1", Locality::Remote, 1, 1, None)]));

        let rows = live.hosts(Window::TenSeconds, Locality::Remote);

        assert_eq!(rows[0].name.as_ref().map(|n| n.name.as_str()), Some("www.cloudflare.com"));
    }

    #[test]
    fn local_and_remote_hosts_are_listed_separately() {
        let mut live = LiveNetwork::default();
        live.add(summary(1, 0, vec![host("192.168.1.86", Locality::Local, 5, 5, None), host("1.1.1.1", Locality::Remote, 5, 5, None)]));

        assert_eq!(live.hosts(Window::TenSeconds, Locality::Local).len(), 1);
        assert_eq!(live.hosts(Window::TenSeconds, Locality::Remote).len(), 1);
    }

    #[test]
    fn quiet_seconds_appear_as_zero_throughput() {
        let mut live = LiveNetwork::default();
        live.add(summary(10, 125, vec![]));
        live.add(summary(13, 250, vec![]));

        let points = live.throughput();

        let rates: Vec<(f64, f64)> = points.iter().map(|p| (p.at_secs, p.inbound_bps)).collect();
        assert_eq!(rates, [(10.0, 1000.0), (11.0, 0.0), (12.0, 0.0), (13.0, 2000.0)]);
    }

    #[test]
    fn only_ten_minutes_of_history_are_kept() {
        let mut live = LiveNetwork::default();
        for second in 0..700 {
            live.add(summary(second, 1, vec![]));
        }

        let points = live.throughput();

        assert_eq!(points.len(), 600);
        assert_eq!(points.first().map(|p| p.at_secs), Some(100.0));
    }

    #[test]
    fn a_hosts_history_has_zero_where_it_was_quiet() {
        let mut live = LiveNetwork::default();
        live.add(summary(1, 0, vec![host("1.1.1.1", Locality::Remote, 7, 3, None)]));
        live.add(summary(2, 0, vec![]));

        let history = live.host_history("1.1.1.1".parse().unwrap());

        assert_eq!(history, [(1.0, 7, 3), (2.0, 0, 0)]);
    }
}
