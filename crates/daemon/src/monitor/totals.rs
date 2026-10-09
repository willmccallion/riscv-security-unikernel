//! Running packet and byte totals, split the ways a summary needs.

use super::decode::{Packet, Transport};
use super::net::Direction;
use std::fmt;
use std::time::Duration;

/// Packets and the bytes they carried on the wire.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counter {
    /// Packets counted.
    pub packets: u64,
    /// Their total length on the wire.
    pub bytes: u64,
}

impl Counter {
    /// Counts one packet of `wire_len` bytes.
    pub fn add(&mut self, wire_len: u32) {
        self.packets += 1;
        self.bytes += u64::from(wire_len);
    }
}

/// Traffic seen over some interval.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TrafficTotals {
    /// From outside to local addresses.
    pub inbound: Counter,
    /// From local addresses to outside.
    pub outbound: Counter,
    /// Between local addresses.
    pub internal: Counter,
    /// Between outside addresses.
    pub transit: Counter,
    /// Frames that were not IP, such as ARP.
    pub non_ip: Counter,
    /// IPv6 packets, whichever direction.
    pub ipv6: Counter,
    /// TCP segments.
    pub tcp: Counter,
    /// UDP datagrams.
    pub udp: Counter,
}

impl TrafficTotals {
    /// Counts one IP packet that went `direction`.
    pub fn record(&mut self, packet: &Packet<'_>, direction: Direction, wire_len: u32) {
        match direction {
            Direction::Inbound => self.inbound.add(wire_len),
            Direction::Outbound => self.outbound.add(wire_len),
            Direction::Internal => self.internal.add(wire_len),
            Direction::Transit => self.transit.add(wire_len),
        }
        if packet.src.is_ipv6() {
            self.ipv6.add(wire_len);
        }
        match packet.transport {
            Transport::Tcp(_) => self.tcp.add(wire_len),
            Transport::Udp(_) => self.udp.add(wire_len),
            Transport::Icmp | Transport::Fragment | Transport::Other(_) => {}
        }
    }

    /// Counts one frame that was not IP.
    pub fn record_non_ip(&mut self, wire_len: u32) {
        self.non_ip.add(wire_len);
    }

    /// IP packets in every direction.
    pub const fn ip(&self) -> Counter {
        Counter {
            packets: self.inbound.packets + self.outbound.packets + self.internal.packets + self.transit.packets,
            bytes: self.inbound.bytes + self.outbound.bytes + self.internal.bytes + self.transit.bytes,
        }
    }

    /// A one-line summary of these totals as rates over `elapsed`.
    pub const fn rates(&self, elapsed: Duration) -> Rates<'_> {
        Rates { totals: self, elapsed }
    }
}

/// [`TrafficTotals`] formatted as per-second rates.
#[derive(Debug)]
pub struct Rates<'a> {
    totals: &'a TrafficTotals,
    elapsed: Duration,
}

impl Rates<'_> {
    fn per_second(&self, count: u64) -> f64 {
        count as f64 / self.elapsed.as_secs_f64().max(1e-9)
    }

    fn write_counter(&self, f: &mut fmt::Formatter<'_>, label: &str, counter: Counter) -> fmt::Result {
        write!(
            f,
            "{label} {:>9}/s {:>7.0} pps",
            SiBits(self.per_second(counter.bytes) * 8.0),
            self.per_second(counter.packets)
        )
    }
}

impl fmt::Display for Rates<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.totals;
        self.write_counter(f, "in", t.inbound)?;
        self.write_counter(f, " | out", t.outbound)?;
        self.write_counter(f, " | local", t.internal)?;
        if t.transit.packets > 0 {
            self.write_counter(f, " | transit", t.transit)?;
        }
        let ip = t.ip();
        let share = |c: Counter| if ip.bytes == 0 { 0.0 } else { 100.0 * c.bytes as f64 / ip.bytes as f64 };
        write!(
            f,
            " | IPv6 {:.0}% TCP {:.0}% UDP {:.0}% of bytes | non-IP {} frames",
            share(t.ipv6),
            share(t.tcp),
            share(t.udp),
            t.non_ip.packets
        )
    }
}

/// A bit rate with an SI prefix, e.g. `12.4 Mb`.
pub struct SiBits(pub f64);

impl fmt::Display for SiBits {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (value, unit) = match self.0 {
            v if v >= 1e9 => (v / 1e9, "Gb"),
            v if v >= 1e6 => (v / 1e6, "Mb"),
            v if v >= 1e3 => (v / 1e3, "kb"),
            v => (v, "b"),
        };
        f.pad(&format!("{value:.1} {unit}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::decode::{TcpFlags, TcpSegment, UdpDatagram};
    use std::net::IpAddr;

    fn packet(src: &str, transport: Transport<'static>) -> Packet<'static> {
        Packet {
            src: src.parse::<IpAddr>().unwrap(),
            dst: src.parse::<IpAddr>().unwrap(),
            transport,
        }
    }

    const TCP: Transport<'static> = Transport::Tcp(TcpSegment {
        src_port: 1,
        dst_port: 2,
        flags: TcpFlags::new(0x10),
        payload: &[],
    });
    const UDP: Transport<'static> = Transport::Udp(UdpDatagram {
        src_port: 1,
        dst_port: 2,
        payload: &[],
    });

    #[test]
    fn packets_are_split_by_direction_family_and_protocol() {
        let mut totals = TrafficTotals::default();

        totals.record(&packet("1.1.1.1", TCP), Direction::Inbound, 1500);
        totals.record(&packet("2001:db8::1", UDP), Direction::Outbound, 100);
        totals.record(&packet("10.0.0.1", Transport::Icmp), Direction::Internal, 64);
        totals.record_non_ip(42);

        assert_eq!(totals.inbound, Counter { packets: 1, bytes: 1500 });
        assert_eq!(totals.outbound, Counter { packets: 1, bytes: 100 });
        assert_eq!(totals.ipv6, Counter { packets: 1, bytes: 100 });
        assert_eq!(totals.tcp.bytes + totals.udp.bytes, 1600);
        assert_eq!(totals.ip(), Counter { packets: 3, bytes: 1664 });
        assert_eq!(totals.non_ip.packets, 1);
    }

    #[test]
    fn rates_read_as_bits_and_packets_per_second() {
        let mut totals = TrafficTotals::default();
        for _ in 0..1000 {
            totals.record(&packet("1.1.1.1", TCP), Direction::Inbound, 1250);
        }

        let line = totals.rates(Duration::from_secs(2)).to_string();

        assert!(line.starts_with("in    5.0 Mb/s     500 pps"), "{line}");
        assert!(line.contains("TCP 100%"), "{line}");
    }
}
