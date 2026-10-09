//! Messages the network monitor streams to its viewers.
//!
//! The monitor writes one JSON object per line to each connected viewer
//! and never reads from them. A viewer first receives [`Message::Hello`],
//! then a [`Message::Summary`] for every second of traffic.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// This protocol's version; a viewer should refuse others.
pub const PROTOCOL_VERSION: u32 = 1;

/// Longest line a viewer should accept, so a confused or hostile peer
/// cannot make it buffer without bound.
pub const MAX_LINE_LEN: usize = 4 * 1024 * 1024;

/// One line of the stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    /// Sent once, first: what the monitor is watching.
    Hello(Hello),
    /// Traffic over one interval.
    Summary(Summary),
}

/// What the monitor is watching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hello {
    /// [`PROTOCOL_VERSION`] of the sender.
    pub protocol: u32,
    /// Interfaces captured on.
    pub interfaces: Vec<String>,
    /// Networks treated as local, as `address/length`.
    pub local_networks: Vec<String>,
    /// Length of each summary's interval, in milliseconds.
    pub interval_ms: u64,
}

/// Packets and the bytes they carried on the wire.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Counter {
    /// Packets.
    pub packets: u64,
    /// Bytes.
    pub bytes: u64,
}

/// Traffic split the ways a viewer charts it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Totals {
    /// From outside to local addresses.
    pub inbound: Counter,
    /// From local addresses to outside.
    pub outbound: Counter,
    /// Between local addresses.
    pub internal: Counter,
    /// Between outside addresses.
    pub transit: Counter,
    /// Frames that were not IP.
    pub non_ip: Counter,
    /// IPv6 packets.
    pub ipv6: Counter,
    /// TCP segments.
    pub tcp: Counter,
    /// UDP datagrams.
    pub udp: Counter,
}

/// Whether a host is on a local network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Locality {
    /// This machine or a neighbour.
    Local,
    /// Anywhere else.
    Remote,
}

/// Where a host's name came from, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NameSource {
    /// The server name a TLS or QUIC client asked it for.
    TlsServerName,
    /// A DNS answer.
    Dns,
    /// Its own mDNS announcement.
    Mdns,
    /// An Encrypted Client Hello's shared cover name.
    TlsCoverName,
}

/// A host's name and where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostName {
    /// The name.
    pub name: String,
    /// Where it came from.
    pub source: NameSource,
}

/// One host's traffic over an interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    /// Its address.
    pub addr: IpAddr,
    /// Whether it is local.
    pub locality: Locality,
    /// Its best known name.
    pub name: Option<HostName>,
    /// What it sent.
    pub sent: Counter,
    /// What it received.
    pub received: Counter,
    /// Flows it started.
    pub flows_opened: u32,
    /// Flows others started with it.
    pub flows_accepted: u32,
}

/// Traffic over one interval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    /// When the interval began, in milliseconds since the Unix epoch.
    pub start_unix_ms: u64,
    /// The interval's length in milliseconds.
    pub length_ms: u64,
    /// What crossed during it.
    pub totals: Totals,
    /// The busiest hosts, busiest first.
    pub hosts: Vec<Host>,
    /// Active hosts beyond those listed.
    pub hosts_omitted: u64,
    /// Flows tracked at the interval's end.
    pub active_flows: u64,
    /// Packets that a full table kept from being attributed.
    pub untracked: u64,
}

impl Message {
    /// The message as one line of JSON, newline included.
    ///
    /// # Errors
    /// Only if serialization fails, which these types cannot cause.
    pub fn to_line(&self) -> serde_json::Result<String> {
        let mut line = serde_json::to_string(self)?;
        line.push('\n');
        Ok(line)
    }

    /// Parses one line of the stream.
    ///
    /// # Errors
    /// If the line is not a message of this protocol.
    pub fn from_line(line: &str) -> serde_json::Result<Self> {
        serde_json::from_str(line.trim_end())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> Summary {
        Summary {
            start_unix_ms: 1_791_525_490_000,
            length_ms: 1000,
            totals: Totals {
                inbound: Counter {
                    packets: 504,
                    bytes: 987_654,
                },
                ..Totals::default()
            },
            hosts: vec![Host {
                addr: "2606:4700::6810:84e5".parse().unwrap(),
                locality: Locality::Remote,
                name: Some(HostName {
                    name: "www.cloudflare.com".into(),
                    source: NameSource::TlsServerName,
                }),
                sent: Counter {
                    packets: 500,
                    bytes: 980_000,
                },
                received: Counter {
                    packets: 400,
                    bytes: 45_000,
                },
                flows_opened: 0,
                flows_accepted: 1,
            }],
            hosts_omitted: 0,
            active_flows: 64,
            untracked: 0,
        }
    }

    #[test]
    fn messages_round_trip_as_single_lines() {
        let message = Message::Summary(summary());

        let line = message.to_line().unwrap();

        assert_eq!(line.matches('\n').count(), 1);
        assert!(line.ends_with('\n'));
        assert_eq!(Message::from_line(&line).unwrap(), message);
    }

    #[test]
    fn the_wire_format_is_tagged_and_readable() {
        let hello = Message::Hello(Hello {
            protocol: PROTOCOL_VERSION,
            interfaces: vec!["enp4s0".into()],
            local_networks: vec!["192.168.1.0/24".into()],
            interval_ms: 1000,
        });

        let line = hello.to_line().unwrap();

        assert!(
            line.starts_with(r#"{"type":"hello","protocol":1,"#),
            "{line}"
        );
        assert!(
            Message::to_line(&Message::Summary(summary()))
                .unwrap()
                .contains(r#""source":"tls_server_name""#)
        );
    }

    #[test]
    fn unknown_message_types_are_rejected() {
        assert!(Message::from_line(r#"{"type":"command","run":"rm -rf /"}"#).is_err());
    }
}
