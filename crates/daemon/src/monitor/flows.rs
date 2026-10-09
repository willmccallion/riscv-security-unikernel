//! Connection tracking: which packets belong to one conversation, and
//! which side started it.

use super::decode::{Packet, TcpFlags, Transport};
use super::time::UnixNanos;
use super::totals::Counter;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

/// How long a flow may sit idle before it is forgotten, by kind.
const TCP_CLOSED_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_OPEN_TIMEOUT: Duration = Duration::from_mins(15);
const UDP_TIMEOUT: Duration = Duration::from_mins(2);
const OTHER_TIMEOUT: Duration = Duration::from_secs(30);

/// Ports from here up are handed out by operating systems for outgoing
/// connections (Linux uses 32768–60999, Windows 49152–65535).
const EPHEMERAL_PORTS_START: u16 = 32_768;
/// Ports below this are well-known services.
const WELL_KNOWN_PORTS_END: u16 = 1024;

/// The transport protocol of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP or ICMPv6.
    Icmp,
    /// Any other IP protocol, by number.
    Other(u8),
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tcp => f.write_str("tcp"),
            Self::Udp => f.write_str("udp"),
            Self::Icmp => f.write_str("icmp"),
            Self::Other(number) => write!(f, "ip-proto-{number}"),
        }
    }
}

/// An address and port; the port is zero for protocols without ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    /// The address.
    pub addr: IpAddr,
    /// The port.
    pub port: u16,
}

/// How a flow's client was identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opening {
    /// The connection's opening (a TCP SYN or SYN-ACK) was seen.
    Seen,
    /// Capture began mid-conversation or the protocol has no handshake;
    /// the client was inferred from the ports.
    Inferred,
}

/// One tracked conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Flow {
    /// Its transport protocol.
    pub protocol: Protocol,
    /// The side that started it.
    pub client: Endpoint,
    /// The side it was started towards.
    pub server: Endpoint,
    /// How the client was identified.
    pub opening: Opening,
    /// When its first packet was seen.
    pub first_seen: UnixNanos,
    /// When its latest packet was seen.
    pub last_seen: UnixNanos,
    /// Traffic from client to server.
    pub from_client: Counter,
    /// Traffic from server to client.
    pub from_server: Counter,
    closing: bool,
}

impl Flow {
    const fn idle_timeout(&self) -> Duration {
        match self.protocol {
            Protocol::Tcp if self.closing => TCP_CLOSED_TIMEOUT,
            Protocol::Tcp => TCP_OPEN_TIMEOUT,
            Protocol::Udp => UDP_TIMEOUT,
            Protocol::Icmp | Protocol::Other(_) => OTHER_TIMEOUT,
        }
    }
}

/// What the flow table worked out about one packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketRole {
    /// The flow's protocol.
    pub protocol: Protocol,
    /// The flow's client.
    pub client: Endpoint,
    /// The flow's server.
    pub server: Endpoint,
    /// Whether the client sent this packet.
    pub from_client: bool,
    /// Whether this packet started a new flow.
    pub opened: bool,
    /// How the client was identified.
    pub opening: Opening,
}

/// Both directions of a conversation map to one key: the endpoints in
/// sorted order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    protocol: Protocol,
    low: Endpoint,
    high: Endpoint,
}

impl FlowKey {
    fn new(protocol: Protocol, a: Endpoint, b: Endpoint) -> Self {
        let (low, high) = if a <= b { (a, b) } else { (b, a) };
        Self { protocol, low, high }
    }
}

/// The packet's endpoints and what its transport header says.
struct Exchange {
    protocol: Protocol,
    sender: Endpoint,
    receiver: Endpoint,
    tcp_flags: Option<TcpFlags>,
}

impl Exchange {
    /// `None` for later fragments, which cannot be placed in a flow.
    const fn of(packet: &Packet<'_>) -> Option<Self> {
        let (protocol, src_port, dst_port, tcp_flags) = match packet.transport {
            Transport::Tcp(t) => (Protocol::Tcp, t.src_port, t.dst_port, Some(t.flags)),
            Transport::Udp(u) => (Protocol::Udp, u.src_port, u.dst_port, None),
            Transport::Icmp => (Protocol::Icmp, 0, 0, None),
            Transport::Other(number) => (Protocol::Other(number), 0, 0, None),
            Transport::Fragment => return None,
        };
        Some(Self {
            protocol,
            sender: Endpoint {
                addr: packet.src,
                port: src_port,
            },
            receiver: Endpoint {
                addr: packet.dst,
                port: dst_port,
            },
            tcp_flags,
        })
    }

    fn opens_tcp_connection(&self) -> bool {
        self.tcp_flags.is_some_and(TcpFlags::is_connection_attempt)
    }

    fn closes_tcp_connection(&self) -> bool {
        self.tcp_flags.is_some_and(TcpFlags::is_close)
    }

    /// Who the client of a newly seen flow is, and how sure that is.
    const fn client(&self) -> (Endpoint, Opening) {
        match self.tcp_flags {
            Some(flags) if flags.is_connection_attempt() => (self.sender, Opening::Seen),
            Some(flags) if flags.is_syn_ack() => (self.receiver, Opening::Seen),
            _ if looks_like_server_port(self.sender.port, self.receiver.port) => (self.receiver, Opening::Inferred),
            _ => (self.sender, Opening::Inferred),
        }
    }
}

/// Whether `port` looks like the server's side of a conversation with
/// `other`: fixed while the other is ephemeral, or well-known while the
/// other is not.
const fn looks_like_server_port(port: u16, other: u16) -> bool {
    let fixed_against_ephemeral = port < EPHEMERAL_PORTS_START && other >= EPHEMERAL_PORTS_START;
    let well_known_against_other = port < WELL_KNOWN_PORTS_END && other >= WELL_KNOWN_PORTS_END;
    fixed_against_ephemeral || well_known_against_other
}

/// Live flows, bounded in number.
#[derive(Debug)]
pub struct FlowTable {
    flows: HashMap<FlowKey, Flow>,
    capacity: usize,
    untracked: u64,
}

impl FlowTable {
    /// An empty table holding at most `capacity` flows.
    pub fn new(capacity: usize) -> Self {
        Self {
            flows: HashMap::new(),
            capacity,
            untracked: 0,
        }
    }

    /// Places a packet in its flow, starting one if needed. Returns
    /// `None` if it cannot be tracked: a later fragment, or a new flow
    /// while the table is full.
    pub fn observe(&mut self, packet: &Packet<'_>, wire_len: u32, at: UnixNanos) -> Option<PacketRole> {
        let exchange = Exchange::of(packet)?;
        let key = FlowKey::new(exchange.protocol, exchange.sender, exchange.receiver);
        let reused = self
            .flows
            .get(&key)
            .is_some_and(|flow| flow.closing && exchange.opens_tcp_connection());
        let opened = reused || !self.flows.contains_key(&key);
        if opened && !reused && self.flows.len() >= self.capacity {
            self.untracked += 1;
            return None;
        }
        if opened {
            let (client, opening) = exchange.client();
            let server = if client == exchange.sender { exchange.receiver } else { exchange.sender };
            let _ = self.flows.insert(
                key,
                Flow {
                    protocol: exchange.protocol,
                    client,
                    server,
                    opening,
                    first_seen: at,
                    last_seen: at,
                    from_client: Counter::default(),
                    from_server: Counter::default(),
                    closing: false,
                },
            );
        }
        let flow = self.flows.get_mut(&key)?;
        let from_client = exchange.sender == flow.client;
        if from_client {
            flow.from_client.add(wire_len);
        } else {
            flow.from_server.add(wire_len);
        }
        flow.last_seen = flow.last_seen.max(at);
        flow.closing |= exchange.closes_tcp_connection();
        Some(PacketRole {
            protocol: flow.protocol,
            client: flow.client,
            server: flow.server,
            from_client,
            opened,
            opening: flow.opening,
        })
    }

    /// Forgets flows idle for longer than their protocol allows.
    pub fn expire(&mut self, now: UnixNanos) {
        self.flows
            .retain(|_, flow| now < flow.last_seen.saturating_add(flow.idle_timeout()));
    }

    /// Flows currently tracked.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// New flows not tracked because the table was full, since the last
    /// call; resets the count.
    pub const fn take_untracked(&mut self) -> u64 {
        std::mem::replace(&mut self.untracked, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::decode::{TcpSegment, UdpDatagram};

    const SYN: u8 = 0x02;
    const SYN_ACK: u8 = 0x12;
    const ACK: u8 = 0x10;
    const FIN_ACK: u8 = 0x11;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn tcp(src: &str, src_port: u16, dst: &str, dst_port: u16, flags: u8) -> Packet<'static> {
        Packet {
            src: ip(src),
            dst: ip(dst),
            transport: Transport::Tcp(TcpSegment {
                src_port,
                dst_port,
                flags: TcpFlags::new(flags),
                payload: &[],
            }),
        }
    }

    fn udp(src: &str, src_port: u16, dst: &str, dst_port: u16) -> Packet<'static> {
        Packet {
            src: ip(src),
            dst: ip(dst),
            transport: Transport::Udp(UdpDatagram {
                src_port,
                dst_port,
                payload: &[],
            }),
        }
    }

    fn at(seconds: u64) -> UnixNanos {
        UnixNanos::new(seconds * 1_000_000_000)
    }

    #[test]
    fn both_directions_share_one_flow_with_the_syn_sender_as_client() {
        let mut table = FlowTable::new(100);

        let syn = table.observe(&tcp("192.168.1.86", 51000, "1.1.1.1", 443, SYN), 60, at(1)).unwrap();
        let reply = table.observe(&tcp("1.1.1.1", 443, "192.168.1.86", 51000, SYN_ACK), 60, at(1)).unwrap();

        assert!(syn.opened && syn.from_client);
        assert!(!reply.opened && !reply.from_client);
        assert_eq!(reply.client.addr, ip("192.168.1.86"));
        assert_eq!((reply.server.port, reply.opening), (443, Opening::Seen));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn a_syn_ack_names_the_client_when_the_syn_was_missed() {
        let mut table = FlowTable::new(100);

        let role = table.observe(&tcp("1.1.1.1", 443, "192.168.1.86", 51000, SYN_ACK), 60, at(1)).unwrap();

        assert_eq!(role.client.addr, ip("192.168.1.86"));
        assert_eq!(role.opening, Opening::Seen);
    }

    #[test]
    fn mid_stream_flows_take_the_fixed_or_well_known_port_as_the_server() {
        let mut table = FlowTable::new(100);

        let download = table.observe(&tcp("1.1.1.1", 443, "192.168.1.86", 51000, ACK), 1500, at(1)).unwrap();
        let dns = table.observe(&udp("8.8.8.8", 53, "192.168.1.86", 5353), 90, at(1)).unwrap();
        let peer = table.observe(&udp("5.5.5.5", 6000, "192.168.1.86", 7000), 90, at(1)).unwrap();

        assert_eq!((download.server.port, download.opening), (443, Opening::Inferred));
        assert_eq!(dns.server.addr, ip("8.8.8.8"));
        assert_eq!(peer.client.addr, ip("5.5.5.5"), "no port hint: the first sender is the client");
    }

    #[test]
    fn idle_flows_expire_by_protocol_and_closed_tcp_goes_first() {
        let mut table = FlowTable::new(100);
        let _ = table.observe(&tcp("10.0.0.1", 40000, "1.1.1.1", 443, SYN), 60, at(0));
        let _ = table.observe(&tcp("10.0.0.2", 40000, "1.1.1.1", 443, SYN), 60, at(0));
        let _ = table.observe(&tcp("10.0.0.2", 40000, "1.1.1.1", 443, FIN_ACK), 60, at(0));
        let _ = table.observe(&udp("10.0.0.3", 40000, "9.9.9.9", 53), 60, at(0));

        table.expire(at(11));
        let after_closed_timeout = table.len();
        table.expire(at(121));
        let after_udp_timeout = table.len();

        assert_eq!(after_closed_timeout, 2);
        assert_eq!(after_udp_timeout, 1);
    }

    #[test]
    fn a_syn_on_a_closed_flow_starts_a_new_one() {
        let mut table = FlowTable::new(100);
        let _ = table.observe(&tcp("10.0.0.1", 40000, "1.1.1.1", 443, SYN), 60, at(0));
        let _ = table.observe(&tcp("1.1.1.1", 443, "10.0.0.1", 40000, FIN_ACK), 60, at(1));

        let again = table.observe(&tcp("10.0.0.1", 40000, "1.1.1.1", 443, SYN), 60, at(2)).unwrap();

        assert!(again.opened);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn a_full_table_counts_new_flows_as_untracked_but_keeps_existing_ones() {
        let mut table = FlowTable::new(1);
        let _ = table.observe(&udp("10.0.0.1", 40000, "9.9.9.9", 53), 60, at(0));

        let new = table.observe(&udp("10.0.0.2", 40000, "9.9.9.9", 53), 60, at(0));
        let existing = table.observe(&udp("9.9.9.9", 53, "10.0.0.1", 40000), 60, at(0));

        assert_eq!(new, None);
        assert!(existing.is_some());
        assert_eq!(table.take_untracked(), 1);
        assert_eq!(table.take_untracked(), 0);
    }

    #[test]
    fn later_fragments_are_not_tracked() {
        let mut table = FlowTable::new(10);
        let fragment = Packet {
            src: ip("1.1.1.1"),
            dst: ip("10.0.0.1"),
            transport: Transport::Fragment,
        };

        assert_eq!(table.observe(&fragment, 60, at(0)), None);
        assert_eq!(table.take_untracked(), 0, "fragments are not a capacity problem");
    }
}
