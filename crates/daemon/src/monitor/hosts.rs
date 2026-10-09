//! Per-host traffic: who sent and received how much, and who started
//! conversations with whom.

use super::flows::PacketRole;
use super::time::UnixNanos;
use super::totals::Counter;
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

/// Hosts idle this long are forgotten.
const HOST_IDLE_TIMEOUT: Duration = Duration::from_hours(1);

/// Whether a host is on a local network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Locality {
    /// On a local network: this machine or a neighbour.
    Local,
    /// Anywhere else.
    Remote,
}

/// One host's traffic over an interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostActivity {
    /// The host's address.
    pub addr: IpAddr,
    /// Whether it is local.
    pub locality: Locality,
    /// What it sent.
    pub sent: Counter,
    /// What it received.
    pub received: Counter,
    /// Flows it started.
    pub flows_opened: u32,
    /// Flows others started with it.
    pub flows_accepted: u32,
}

impl HostActivity {
    const fn idle(addr: IpAddr, locality: Locality) -> Self {
        Self {
            addr,
            locality,
            sent: Counter { packets: 0, bytes: 0 },
            received: Counter { packets: 0, bytes: 0 },
            flows_opened: 0,
            flows_accepted: 0,
        }
    }

    /// Bytes in both directions.
    pub const fn bytes(&self) -> u64 {
        self.sent.bytes + self.received.bytes
    }

    const fn is_idle(&self) -> bool {
        self.sent.packets == 0 && self.received.packets == 0
    }
}

#[derive(Debug, Clone, Copy)]
struct HostEntry {
    last_seen: UnixNanos,
    interval: HostActivity,
}

/// Every host seen recently, bounded in number.
#[derive(Debug)]
pub struct HostTable {
    hosts: HashMap<IpAddr, HostEntry>,
    capacity: usize,
    untracked: u64,
}

/// One end of a packet, as the host table records it.
#[derive(Debug, Clone, Copy)]
pub struct PacketEnd {
    /// The host's address.
    pub addr: IpAddr,
    /// Whether it is local.
    pub locality: Locality,
}

impl HostTable {
    /// An empty table holding at most `capacity` hosts.
    pub fn new(capacity: usize) -> Self {
        Self {
            hosts: HashMap::new(),
            capacity,
            untracked: 0,
        }
    }

    /// Counts a packet of `wire_len` bytes from `sender` to `receiver`;
    /// an end that is not a single host, such as a broadcast address, is
    /// `None` and not tracked. `role`, when the packet opened a flow,
    /// credits whichever host started it.
    pub fn record(
        &mut self,
        sender: Option<PacketEnd>,
        receiver: Option<PacketEnd>,
        wire_len: u32,
        role: Option<&PacketRole>,
        at: UnixNanos,
    ) {
        let opened_by_sender = role.filter(|r| r.opened).map(|r| r.from_client);
        if let Some(host) = sender.and_then(|end| self.entry(end, at)) {
            host.sent.add(wire_len);
            match opened_by_sender {
                Some(true) => host.flows_opened += 1,
                Some(false) => host.flows_accepted += 1,
                None => {}
            }
        }
        if let Some(host) = receiver.and_then(|end| self.entry(end, at)) {
            host.received.add(wire_len);
            match opened_by_sender {
                Some(true) => host.flows_accepted += 1,
                Some(false) => host.flows_opened += 1,
                None => {}
            }
        }
    }

    /// The activity of every host active since the last call, busiest
    /// first; starts a new interval.
    pub fn close_interval(&mut self) -> Vec<HostActivity> {
        let mut active: Vec<HostActivity> = Vec::new();
        for entry in self.hosts.values_mut() {
            if !entry.interval.is_idle() {
                active.push(entry.interval);
            }
            entry.interval = HostActivity::idle(entry.interval.addr, entry.interval.locality);
        }
        active.sort_by(|a, b| b.bytes().cmp(&a.bytes()).then(a.addr.cmp(&b.addr)));
        active
    }

    /// Forgets hosts idle for an hour.
    pub fn expire(&mut self, now: UnixNanos) {
        self.hosts
            .retain(|_, host| now < host.last_seen.saturating_add(HOST_IDLE_TIMEOUT));
    }

    /// Packets whose host could not be tracked because the table was
    /// full, since the last call; resets the count.
    pub const fn take_untracked(&mut self) -> u64 {
        std::mem::replace(&mut self.untracked, 0)
    }

    fn entry(&mut self, end: PacketEnd, at: UnixNanos) -> Option<&mut HostActivity> {
        if !self.hosts.contains_key(&end.addr) && self.hosts.len() >= self.capacity {
            self.untracked += 1;
            return None;
        }
        let entry = self.hosts.entry(end.addr).or_insert_with(|| HostEntry {
            last_seen: at,
            interval: HostActivity::idle(end.addr, end.locality),
        });
        entry.last_seen = entry.last_seen.max(at);
        Some(&mut entry.interval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::flows::{Endpoint, Opening, Protocol};

    fn end(addr: &str, locality: Locality) -> PacketEnd {
        PacketEnd {
            addr: addr.parse().unwrap(),
            locality,
        }
    }

    fn opened_by_client(from_client: bool) -> PacketRole {
        let endpoint = Endpoint {
            addr: "0.0.0.0".parse().unwrap(),
            port: 0,
        };
        PacketRole {
            protocol: Protocol::Tcp,
            client: endpoint,
            server: endpoint,
            from_client,
            opened: true,
            opening: Opening::Seen,
        }
    }

    #[test]
    fn senders_and_receivers_are_credited_and_sorted_busiest_first() {
        let mut table = HostTable::new(10);
        let me = end("192.168.1.86", Locality::Local);
        let cdn = end("1.1.1.1", Locality::Remote);
        let dns = end("9.9.9.9", Locality::Remote);

        table.record(Some(me), Some(cdn), 100, Some(&opened_by_client(true)), UnixNanos::new(0));
        table.record(Some(cdn), Some(me), 1500, None, UnixNanos::new(1));
        table.record(Some(me), Some(dns), 80, None, UnixNanos::new(2));
        let active = table.close_interval();

        let addrs: Vec<String> = active.iter().map(|h| h.addr.to_string()).collect();
        assert_eq!(addrs, ["192.168.1.86", "1.1.1.1", "9.9.9.9"]);
        assert_eq!((active[0].flows_opened, active[1].flows_accepted), (1, 1));
        assert_eq!(active[1].sent.bytes, 1500);
        assert_eq!(active[1].locality, Locality::Remote);
    }

    #[test]
    fn closing_an_interval_resets_activity_but_remembers_hosts() {
        let mut table = HostTable::new(1);
        let a = end("10.0.0.1", Locality::Local);
        table.record(Some(a), Some(a), 10, None, UnixNanos::new(0));
        let _ = table.close_interval();

        let quiet = table.close_interval();
        table.record(Some(end("10.0.0.2", Locality::Local)), Some(a), 10, None, UnixNanos::new(1));

        assert!(quiet.is_empty());
        assert_eq!(table.take_untracked(), 1, "the table is full of the remembered host");
    }

    #[test]
    fn hosts_idle_for_an_hour_are_forgotten() {
        let mut table = HostTable::new(1);
        let a = end("10.0.0.1", Locality::Local);
        table.record(Some(a), Some(a), 10, None, UnixNanos::new(0));

        table.expire(UnixNanos::new(3_600 * 1_000_000_000));
        let b = end("10.0.0.2", Locality::Local);
        table.record(Some(b), Some(b), 10, None, UnixNanos::new(1));

        assert_eq!(table.take_untracked(), 0);
    }
}
