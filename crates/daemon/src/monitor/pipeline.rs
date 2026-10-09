//! The monitor's processing core, independent of where frames come from.

use super::decode::{self, LinkType, NotIp, Packet, Transport};
use super::dns;
use super::quic;
use super::tls::ServerName;
use super::flows::{FlowTable, PacketRole};
use super::hosts::{HostActivity, HostTable, Locality, PacketEnd};
use super::names::{HelloAssembler, HostName, NameSource, NameTable};
use super::net::LocalNetworks;
use super::time::UnixNanos;
use super::totals::TrafficTotals;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

/// Most flows tracked at once (roughly 100 bytes each).
const FLOW_CAPACITY: usize = 262_144;
/// Most hosts tracked at once.
const HOST_CAPACITY: usize = 65_536;
/// Most hosts listed in one summary, busiest first.
const HOSTS_PER_SUMMARY: usize = 256;
/// Most host names remembered at once.
const NAME_CAPACITY: usize = 65_536;
const DNS_PORT: u16 = 53;
const MDNS_PORT: u16 = 5353;

/// What the monitor could not decode, and how naming went, over one
/// interval; shown with `--verbose`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diagnostics {
    /// Frames that were not IP, by why.
    pub not_ip: BTreeMap<NotIp, u64>,
    /// DNS responses read.
    pub dns_responses: u64,
    /// mDNS responses read.
    pub mdns_responses: u64,
    /// Client TCP segments that began like a TLS handshake.
    pub tls_hellos_seen: u64,
    /// Server names read from TLS over TCP.
    pub tls_names: u64,
    /// Client QUIC Initial packets decrypted.
    pub quic_initials: u64,
    /// Server names read from QUIC.
    pub quic_names: u64,
}

/// A host listed in a summary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedHost {
    /// Its traffic over the interval.
    pub activity: HostActivity,
    /// Its best known name.
    pub name: Option<HostName>,
}

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
    pub hosts: Vec<ListedHost>,
    /// Active hosts beyond those listed.
    pub hosts_omitted: usize,
    /// Flows being tracked at the interval's end.
    pub active_flows: usize,
    /// Packets that could not be attributed to a flow or host because a
    /// table was full; non-zero means the traffic exceeds what the monitor
    /// can follow.
    pub untracked: u64,
    /// Decoding and naming counts.
    pub diagnostics: Diagnostics,
}

/// Turns timestamped frames into per-interval summaries.
///
/// Intervals are aligned to the epoch, so live and replayed traffic split
/// the same way. Time comes from the frames; a live capture also calls
/// [`Monitor::tick`] so a quiet interval still closes on time.
#[derive(Debug)]
pub struct Monitor {
    local: LocalNetworks,
    interval: Duration,
    current: Option<OpenInterval>,
    /// The end of the last interval closed; nothing is counted before it.
    closed_until: UnixNanos,
    flows: FlowTable,
    hosts: HostTable,
    names: NameTable,
    hellos: HelloAssembler,
    diagnostics: Diagnostics,
}

#[derive(Debug, Clone, Copy)]
struct OpenInterval {
    start: UnixNanos,
    totals: TrafficTotals,
}

impl Monitor {
    /// A monitor judging direction against `local`, summarising every
    /// `interval`.
    pub fn new(local: LocalNetworks, interval: Duration) -> Self {
        Self {
            local,
            interval,
            current: None,
            closed_until: UnixNanos::new(0),
            flows: FlowTable::new(FLOW_CAPACITY),
            hosts: HostTable::new(HOST_CAPACITY),
            names: NameTable::new(NAME_CAPACITY),
            hellos: HelloAssembler::default(),
            diagnostics: Diagnostics::default(),
        }
    }

    /// The networks treated as local.
    pub const fn local_networks(&self) -> &LocalNetworks {
        &self.local
    }

    /// Counts a frame of `link` type captured at `at` whose wire length
    /// was `wire_len`. Returns the previous interval's summary if this
    /// frame begins a new one. A frame stamped before the open interval,
    /// or inside one already closed, counts toward the next one open: the
    /// kernel hands over frames in blocks, so a frame can arrive after
    /// the wall clock has closed the interval it was captured in.
    pub fn observe(&mut self, link: LinkType, frame: &[u8], wire_len: u32, at: UnixNanos) -> Option<Summary> {
        let closed = self.tick(at);
        let at = at.max(self.closed_until);
        let open = self.current.get_or_insert_with(|| OpenInterval {
            start: at.floor_to(self.interval),
            totals: TrafficTotals::default(),
        });
        if let Some(packet) = decode::decode(link, frame) {
            let direction = self.local.direction(packet.src, packet.dst);
            open.totals.record(&packet, direction, wire_len);
            self.track(&packet, wire_len, at);
        } else {
            open.totals.record_non_ip(wire_len);
            *self.diagnostics.not_ip.entry(decode::classify_rejected(link, frame)).or_default() += 1;
        }
        closed
    }

    fn track(&mut self, packet: &Packet<'_>, wire_len: u32, at: UnixNanos) {
        let role = self.flows.observe(packet, wire_len, at);
        self.learn_names(packet, role.as_ref(), at);
        let sender = self.end(packet.src);
        let receiver = self.end(packet.dst);
        self.hosts.record(sender, receiver, wire_len, role.as_ref(), at);
    }

    /// Learns names from DNS and mDNS responses, and from the server name
    /// in a TLS client's hello, over TCP or QUIC.
    fn learn_names(&mut self, packet: &Packet<'_>, role: Option<&PacketRole>, at: UnixNanos) {
        match packet.transport {
            Transport::Udp(udp) => {
                if let Some(role) = role.filter(|r| r.from_client) {
                    let crypto = quic::client_initial_crypto(udp.payload);
                    if !crypto.is_empty() {
                        self.diagnostics.quic_initials += 1;
                    }
                    if let Some(hello) = self.hellos.observe_quic(role.client, role.server, &crypto, at) {
                        self.diagnostics.quic_names += 1;
                        self.learn_server_name(role.server.addr, &hello, at);
                    }
                }
                let (source, counter) = match udp.src_port {
                    DNS_PORT => (NameSource::Dns, &mut self.diagnostics.dns_responses),
                    MDNS_PORT => (NameSource::Mdns, &mut self.diagnostics.mdns_responses),
                    _ => return,
                };
                if let Some(response) = dns::parse_response(udp.payload) {
                    *counter += 1;
                    self.names.learn_from_dns(&response, source, at);
                }
            }
            Transport::Tcp(tcp) => {
                let Some(role) = role.filter(|r| r.from_client) else { return };
                if tcp.payload.starts_with(&[22, 3]) {
                    self.diagnostics.tls_hellos_seen += 1;
                }
                if let Some(hello) = self.hellos.observe_tcp(role.client, role.server, tcp.sequence, tcp.payload, at) {
                    self.diagnostics.tls_names += 1;
                    self.learn_server_name(role.server.addr, &hello, at);
                }
            }
            Transport::Icmp | Transport::Fragment | Transport::Other(_) => {}
        }
    }

    fn learn_server_name(&mut self, server: IpAddr, hello: &ServerName, at: UnixNanos) {
        let source = if hello.encrypted_hello { NameSource::TlsCoverName } else { NameSource::TlsServerName };
        self.names.learn(server, &hello.name, source, at);
    }

    /// The host at `addr`, or `None` if `addr` is not a single host.
    fn end(&self, addr: IpAddr) -> Option<PacketEnd> {
        if !self.local.is_host_address(addr) {
            return None;
        }
        let locality = if self.local.contains(addr) { Locality::Local } else { Locality::Remote };
        Some(PacketEnd { addr, locality })
    }

    /// Closes the open interval if `now` is past its end.
    pub fn tick(&mut self, now: UnixNanos) -> Option<Summary> {
        let open = self.current?;
        if now < open.start.saturating_add(self.interval) {
            return None;
        }
        self.current = None;
        self.closed_until = open.start.saturating_add(self.interval);
        let summary = self.summarise(open);
        self.flows.expire(now);
        self.hosts.expire(now);
        self.names.expire(now);
        self.hellos.expire(now);
        Some(summary)
    }

    /// Closes the open interval however far it got, as at the end of a
    /// capture file.
    pub fn finish(&mut self) -> Option<Summary> {
        let open = self.current.take()?;
        Some(self.summarise(open))
    }

    fn summarise(&mut self, open: OpenInterval) -> Summary {
        let active = self.hosts.close_interval();
        let hosts_omitted = active.len().saturating_sub(HOSTS_PER_SUMMARY);
        let hosts = active
            .into_iter()
            .take(HOSTS_PER_SUMMARY)
            .map(|activity| ListedHost {
                name: self.names.lookup(activity.addr).cloned(),
                activity,
            })
            .collect();
        Summary {
            start: open.start,
            length: self.interval,
            totals: open.totals,
            hosts,
            hosts_omitted,
            active_flows: self.flows.active_count(),
            untracked: self.flows.take_untracked() + self.hosts.take_untracked(),
            diagnostics: std::mem::take(&mut self.diagnostics),
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
        Monitor::new(local, Duration::from_secs(1))
    }

    #[test]
    fn a_frame_in_the_next_interval_closes_the_previous_one() {
        let mut m = monitor();
        let frame = udp_frame();

        let first = m.observe(LinkType::Ethernet, &frame, 60, UnixNanos::new(10 * SECOND + 5));
        let second = m.observe(LinkType::Ethernet, &frame, 60, UnixNanos::new(10 * SECOND + 900));
        let closed = m.observe(LinkType::Ethernet, &frame, 60, UnixNanos::new(11 * SECOND)).unwrap();

        assert_eq!((first, second), (None, None));
        assert_eq!(closed.start, UnixNanos::new(10 * SECOND));
        assert_eq!(closed.totals.inbound.packets, 2);
    }

    #[test]
    fn a_quiet_interval_closes_on_tick() {
        let mut m = monitor();
        let _ = m.observe(LinkType::Ethernet, &udp_frame(), 60, UnixNanos::new(3 * SECOND + 1));

        let early = m.tick(UnixNanos::new(3 * SECOND + SECOND / 2));
        let due = m.tick(UnixNanos::new(4 * SECOND));

        assert_eq!(early, None);
        assert_eq!(due.unwrap().totals.inbound.bytes, 60);
        assert_eq!(m.tick(UnixNanos::new(9 * SECOND)), None, "nothing open after closing");
    }

    #[test]
    fn late_frames_count_toward_the_open_interval() {
        let mut m = monitor();
        let _ = m.observe(LinkType::Ethernet, &udp_frame(), 60, UnixNanos::new(5 * SECOND + 10));

        let late = m.observe(LinkType::Ethernet, &udp_frame(), 60, UnixNanos::new(4 * SECOND + 999));

        assert_eq!(late, None);
        assert_eq!(m.finish().unwrap().totals.inbound.packets, 2);
    }

    #[test]
    fn non_ip_frames_are_counted_separately() {
        let mut m = monitor();
        let mut arp = vec![0u8; 12];
        arp.extend_from_slice(&[0x08, 0x06]);
        arp.extend_from_slice(&[0; 28]);

        let _ = m.observe(LinkType::Ethernet, &arp, 42, UnixNanos::new(SECOND));

        let summary = m.finish().unwrap();
        assert_eq!(summary.totals.non_ip.packets, 1);
        assert_eq!(summary.totals.ip().packets, 0);
        assert_eq!(summary.diagnostics.not_ip.get(&NotIp::EtherType(0x0806)), Some(&1));
    }

    #[test]
    fn summaries_list_active_hosts_and_flows() {
        let mut m = monitor();

        let _ = m.observe(LinkType::Ethernet, &udp_frame(), 60, UnixNanos::new(SECOND));
        let summary = m.finish().unwrap();

        let addrs: Vec<String> = summary.hosts.iter().map(|h| h.activity.addr.to_string()).collect();
        assert_eq!(addrs, ["1.1.1.1", "192.168.1.86"]);
        assert_eq!(summary.hosts[0].activity.locality, Locality::Remote);
        assert_eq!(summary.active_flows, 1);
        assert_eq!(summary.untracked, 0);
    }

    #[test]
    fn dns_answers_name_the_hosts_in_summaries() {
        let mut m = monitor();
        let answer = [
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 3, b'o', b'n', b'e', 3, b'o', b'n', b'e', 0, 0, 1, 0, 1, 0xC0,
            12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 1, 1, 1,
        ];
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x08, 0x00]);
        let total = u16::try_from(20 + 8 + answer.len()).unwrap();
        frame.extend_from_slice(&[0x45, 0, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 1, 1, 1, 1, 192, 168, 1, 86]);
        frame[16..18].copy_from_slice(&total.to_be_bytes());
        frame.extend_from_slice(&[0, 53, 0x9C, 0x40]);
        frame.extend_from_slice(&u16::try_from(8 + answer.len()).unwrap().to_be_bytes());
        frame.extend_from_slice(&[0, 0]);
        frame.extend_from_slice(&answer);

        let _ = m.observe(LinkType::Ethernet, &frame, 90, UnixNanos::new(SECOND));
        let summary = m.finish().unwrap();

        assert_eq!(summary.diagnostics.dns_responses, 1);
        let resolver = summary.hosts.iter().find(|h| h.activity.addr.to_string() == "1.1.1.1").unwrap();
        assert_eq!(resolver.name.as_ref().map(|n| &*n.name), Some("one.one"));
    }

    #[test]
    fn a_frame_arriving_after_its_interval_closed_never_reopens_it() {
        let mut m = monitor();
        let _ = m.observe(LinkType::Ethernet, &udp_frame(), 60, UnixNanos::new(12 * SECOND + 1));
        let closed = m.tick(UnixNanos::new(13 * SECOND + 5)).unwrap();

        let _ = m.observe(LinkType::Ethernet, &udp_frame(), 60, UnixNanos::new(12 * SECOND + 995_000_000));
        let next = m.finish().unwrap();

        assert_eq!(closed.start, UnixNanos::new(12 * SECOND));
        assert_eq!(next.start, UnixNanos::new(13 * SECOND), "the late frame joins the next second");
        assert_eq!(next.totals.inbound.packets, 1);
    }
}
