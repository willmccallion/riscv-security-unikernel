//! The monitor's processing core, independent of where frames come from.

use super::decode::{self, LinkType, Packet};
use super::flows::FlowTable;
use super::hosts::{HostActivity, HostTable, Locality, PacketEnd};
use super::net::LocalNetworks;
use super::time::UnixNanos;
use super::totals::TrafficTotals;
use std::net::IpAddr;
use std::time::Duration;

/// Most flows tracked at once (roughly 100 bytes each).
const FLOW_CAPACITY: usize = 262_144;
/// Most hosts tracked at once.
const HOST_CAPACITY: usize = 65_536;
/// Most hosts listed in one summary, busiest first.
const HOSTS_PER_SUMMARY: usize = 256;

/// Traffic over one closed interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// When the interval began.
    pub start: UnixNanos,
    /// The interval's length.
    pub length: Duration,
    /// What crossed during it.
    pub totals: TrafficTotals,
    /// The busiest hosts active during it, busiest first.
    pub hosts: Vec<HostActivity>,
    /// Active hosts beyond those listed.
    pub hosts_omitted: usize,
    /// Flows being tracked at the interval's end.
    pub active_flows: usize,
    /// Packets that could not be attributed to a flow or host because a
    /// table was full; non-zero means the traffic exceeds what the monitor
    /// can follow.
    pub untracked: u64,
}

/// Turns timestamped frames into per-interval summaries.
///
/// Intervals are aligned to the epoch, so live and replayed traffic split
/// the same way. Time comes from the frames; a live capture also calls
/// [`Monitor::tick`] so a quiet interval still closes on time.
#[derive(Debug)]
pub struct Monitor {
    link: LinkType,
    local: LocalNetworks,
    interval: Duration,
    current: Option<OpenInterval>,
    flows: FlowTable,
    hosts: HostTable,
}

#[derive(Debug, Clone, Copy)]
struct OpenInterval {
    start: UnixNanos,
    totals: TrafficTotals,
}

impl Monitor {
    /// A monitor for frames of `link` type, judging direction against
    /// `local`, summarising every `interval`.
    pub fn new(link: LinkType, local: LocalNetworks, interval: Duration) -> Self {
        Self {
            link,
            local,
            interval,
            current: None,
            flows: FlowTable::new(FLOW_CAPACITY),
            hosts: HostTable::new(HOST_CAPACITY),
        }
    }

    /// The networks treated as local.
    pub const fn local_networks(&self) -> &LocalNetworks {
        &self.local
    }

    /// Counts a frame captured at `at` whose wire length was `wire_len`.
    /// Returns the previous interval's summary if this frame begins a new
    /// one. A frame stamped earlier than the open interval, as captures
    /// from several queues can be, counts toward the open interval.
    pub fn observe(&mut self, frame: &[u8], wire_len: u32, at: UnixNanos) -> Option<Summary> {
        let closed = self.tick(at);
        let open = self.current.get_or_insert_with(|| OpenInterval {
            start: at.floor_to(self.interval),
            totals: TrafficTotals::default(),
        });
        match decode::decode(self.link, frame) {
            Some(packet) => {
                let direction = self.local.direction(packet.src, packet.dst);
                open.totals.record(&packet, direction, wire_len);
                self.track(&packet, wire_len, at);
            }
            None => open.totals.record_non_ip(wire_len),
        }
        closed
    }

    fn track(&mut self, packet: &Packet<'_>, wire_len: u32, at: UnixNanos) {
        let role = self.flows.observe(packet, wire_len, at);
        let sender = self.end(packet.src);
        let receiver = self.end(packet.dst);
        self.hosts.record(sender, receiver, wire_len, role.as_ref(), at);
    }

    fn end(&self, addr: IpAddr) -> PacketEnd {
        let locality = if self.local.contains(addr) { Locality::Local } else { Locality::Remote };
        PacketEnd { addr, locality }
    }

    /// Closes the open interval if `now` is past its end.
    pub fn tick(&mut self, now: UnixNanos) -> Option<Summary> {
        let open = self.current?;
        if now < open.start.saturating_add(self.interval) {
            return None;
        }
        self.current = None;
        let summary = self.summarise(open);
        self.flows.expire(now);
        self.hosts.expire(now);
        Some(summary)
    }

    /// Closes the open interval however far it got, as at the end of a
    /// capture file.
    pub fn finish(&mut self) -> Option<Summary> {
        let open = self.current.take()?;
        Some(self.summarise(open))
    }

    fn summarise(&mut self, open: OpenInterval) -> Summary {
        let mut hosts = self.hosts.close_interval();
        let hosts_omitted = hosts.len().saturating_sub(HOSTS_PER_SUMMARY);
        hosts.truncate(HOSTS_PER_SUMMARY);
        Summary {
            start: open.start,
            length: self.interval,
            totals: open.totals,
            hosts,
            hosts_omitted,
            active_flows: self.flows.len(),
            untracked: self.flows.take_untracked() + self.hosts.take_untracked(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: u64 = 1_000_000_000;

    fn udp_frame() -> Vec<u8> {
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x08, 0x00]);
        frame.extend_from_slice(&[0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 1, 1, 1, 1, 192, 168, 1, 86]);
        frame.extend_from_slice(&[0, 53, 0x9C, 0x40, 0, 8, 0, 0]);
        frame
    }

    fn monitor() -> Monitor {
        let local = LocalNetworks::new(vec!["192.168.1.0/24".parse().unwrap()]);
        Monitor::new(LinkType::Ethernet, local, Duration::from_secs(1))
    }

    #[test]
    fn a_frame_in_the_next_interval_closes_the_previous_one() {
        let mut m = monitor();
        let frame = udp_frame();

        let first = m.observe(&frame, 60, UnixNanos::new(10 * SECOND + 5));
        let second = m.observe(&frame, 60, UnixNanos::new(10 * SECOND + 900));
        let closed = m.observe(&frame, 60, UnixNanos::new(11 * SECOND)).unwrap();

        assert_eq!((first, second), (None, None));
        assert_eq!(closed.start, UnixNanos::new(10 * SECOND));
        assert_eq!(closed.totals.inbound.packets, 2);
    }

    #[test]
    fn a_quiet_interval_closes_on_tick() {
        let mut m = monitor();
        let _ = m.observe(&udp_frame(), 60, UnixNanos::new(3 * SECOND + 1));

        let early = m.tick(UnixNanos::new(3 * SECOND + SECOND / 2));
        let due = m.tick(UnixNanos::new(4 * SECOND));

        assert_eq!(early, None);
        assert_eq!(due.unwrap().totals.inbound.bytes, 60);
        assert_eq!(m.tick(UnixNanos::new(9 * SECOND)), None, "nothing open after closing");
    }

    #[test]
    fn late_frames_count_toward_the_open_interval() {
        let mut m = monitor();
        let _ = m.observe(&udp_frame(), 60, UnixNanos::new(5 * SECOND + 10));

        let late = m.observe(&udp_frame(), 60, UnixNanos::new(4 * SECOND + 999));

        assert_eq!(late, None);
        assert_eq!(m.finish().unwrap().totals.inbound.packets, 2);
    }

    #[test]
    fn non_ip_frames_are_counted_separately() {
        let mut m = monitor();
        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&[0x08, 0x06]);
        arp.extend_from_slice(&[0; 28]);

        let _ = m.observe(&arp, 42, UnixNanos::new(SECOND));

        let summary = m.finish().unwrap();
        assert_eq!(summary.totals.non_ip.packets, 1);
        assert_eq!(summary.totals.ip().packets, 0);
    }

    #[test]
    fn summaries_list_active_hosts_and_flows() {
        let mut m = monitor();

        let _ = m.observe(&udp_frame(), 60, UnixNanos::new(SECOND));
        let summary = m.finish().unwrap();

        let addrs: Vec<String> = summary.hosts.iter().map(|h| h.addr.to_string()).collect();
        assert_eq!(addrs, ["1.1.1.1", "192.168.1.86"]);
        assert_eq!(summary.hosts[0].locality, Locality::Remote);
        assert_eq!(summary.active_flows, 1);
        assert_eq!(summary.untracked, 0);
    }
}
