//! The monitor's processing core, independent of where frames come from.

use super::decode::{self, LinkType};
use super::net::LocalNetworks;
use super::time::UnixNanos;
use super::totals::TrafficTotals;
use std::time::Duration;

/// Traffic over one closed interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    /// When the interval began.
    pub start: UnixNanos,
    /// The interval's length.
    pub length: Duration,
    /// What crossed during it.
    pub totals: TrafficTotals,
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
}

#[derive(Debug, Clone, Copy)]
struct OpenInterval {
    start: UnixNanos,
    totals: TrafficTotals,
}

impl Monitor {
    /// A monitor for frames of `link` type, judging direction against
    /// `local`, summarising every `interval`.
    pub const fn new(link: LinkType, local: LocalNetworks, interval: Duration) -> Self {
        Self {
            link,
            local,
            interval,
            current: None,
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
            }
            None => open.totals.record_non_ip(wire_len),
        }
        closed
    }

    /// Closes the open interval if `now` is past its end.
    pub fn tick(&mut self, now: UnixNanos) -> Option<Summary> {
        let open = self.current?;
        if now < open.start.saturating_add(self.interval) {
            return None;
        }
        self.current = None;
        Some(self.summarise(open))
    }

    /// Closes the open interval however far it got, as at the end of a
    /// capture file.
    pub fn finish(&mut self) -> Option<Summary> {
        self.current.take().map(|open| self.summarise(open))
    }

    const fn summarise(&self, open: OpenInterval) -> Summary {
        Summary {
            start: open.start,
            length: self.interval,
            totals: open.totals,
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
}
