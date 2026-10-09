//! Naming hosts from what their traffic reveals: TLS server names, DNS
//! answers and mDNS announcements.

use super::dns::{DnsResponse, NamedAddress};
use super::flows::Endpoint;
use super::time::UnixNanos;
use super::tls::{self, Hello, ServerName};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

/// Names unrefreshed this long are forgotten.
const NAME_LIFETIME: Duration = Duration::from_hours(24);
/// A better-ranked name stops winning once it is this old.
const NAME_FRESHNESS: Duration = Duration::from_hours(1);
/// Most bytes of a client stream buffered to read its ClientHello.
const MAX_HELLO_BYTES: usize = 16 * 1024;
/// Streams whose hello has not completed in this long are given up on.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
/// Most hellos being assembled at once.
const MAX_PENDING_HELLOS: usize = 1024;

/// Where a name came from, best first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NameSource {
    /// The server name a TLS client asked this host for.
    TlsServerName,
    /// A DNS answer that gave this address.
    Dns,
    /// The host's own mDNS announcement.
    Mdns,
    /// A TLS server name from an Encrypted Client Hello: only a cover
    /// name shared by many sites.
    TlsCoverName,
}

/// A host's name and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostName {
    /// The name.
    pub name: Arc<str>,
    /// Where it came from.
    pub source: NameSource,
}

#[derive(Debug, Clone)]
struct NameEntry {
    name: HostName,
    learned_at: UnixNanos,
}

/// The best known name of each recently named address, bounded in
/// number.
#[derive(Debug)]
pub struct NameTable {
    names: HashMap<IpAddr, NameEntry>,
    capacity: usize,
}

impl NameTable {
    /// An empty table holding at most `capacity` names.
    pub fn new(capacity: usize) -> Self {
        Self {
            names: HashMap::new(),
            capacity,
        }
    }

    /// Records that `addr` goes by `name`. It replaces the current name if
    /// it comes from an equal or better source, or if the current one is
    /// over an hour old.
    pub fn learn(&mut self, addr: IpAddr, name: &str, source: NameSource, at: UnixNanos) {
        if let Some(entry) = self.names.get(&addr) {
            let stale = at >= entry.learned_at.saturating_add(NAME_FRESHNESS);
            if source > entry.name.source && !stale {
                return;
            }
        } else if self.names.len() >= self.capacity {
            return;
        }
        let name = HostName {
            name: Arc::from(name),
            source,
        };
        let _ = self.names.insert(addr, NameEntry { name, learned_at: at });
    }

    /// Records every address a DNS or mDNS response gave.
    pub fn learn_from_dns(&mut self, response: &DnsResponse, source: NameSource, at: UnixNanos) {
        for NamedAddress { name, addr, .. } in &response.addresses {
            self.learn(*addr, name, source, at);
        }
    }

    /// The best known name of `addr`.
    pub fn lookup(&self, addr: IpAddr) -> Option<&HostName> {
        self.names.get(&addr).map(|entry| &entry.name)
    }

    /// Forgets names not refreshed for a day.
    pub fn expire(&mut self, now: UnixNanos) {
        self.names
            .retain(|_, entry| now < entry.learned_at.saturating_add(NAME_LIFETIME));
    }
}

/// The start of one client stream, reassembled by sequence number until
/// its ClientHello can be read.
#[derive(Debug)]
struct PendingHello {
    first_sequence: u32,
    bytes: Vec<u8>,
    received: Vec<bool>,
    started: UnixNanos,
}

impl PendingHello {
    fn write(&mut self, sequence: u32, payload: &[u8]) {
        let offset = sequence.wrapping_sub(self.first_sequence) as usize;
        if offset >= MAX_HELLO_BYTES {
            return;
        }
        let end = (offset + payload.len()).min(MAX_HELLO_BYTES);
        if self.bytes.len() < end {
            self.bytes.resize(end, 0);
            self.received.resize(end, false);
        }
        self.bytes[offset..end].copy_from_slice(&payload[..end - offset]);
        self.received[offset..end].fill(true);
    }

    fn contiguous(&self) -> &[u8] {
        let len = self.received.iter().take_while(|&&r| r).count();
        &self.bytes[..len]
    }
}

/// Reassembles the first bytes of TLS client streams to read their
/// server names, bounded in number, size and age.
#[derive(Debug, Default)]
pub struct HelloAssembler {
    pending: HashMap<(Endpoint, Endpoint), PendingHello>,
}

impl HelloAssembler {
    /// Feeds a segment the client sent the server; returns the server
    /// name once the ClientHello is complete. Only streams that begin like
    /// a TLS handshake are buffered.
    pub fn observe(&mut self, client: Endpoint, server: Endpoint, sequence: u32, payload: &[u8], at: UnixNanos) -> Option<ServerName> {
        if payload.is_empty() {
            return None;
        }
        let key = (client, server);
        if !self.pending.contains_key(&key) {
            let looks_like_handshake = payload.starts_with(&[22, 3]);
            if !looks_like_handshake || self.pending.len() >= MAX_PENDING_HELLOS {
                return None;
            }
            let _ = self.pending.insert(
                key,
                PendingHello {
                    first_sequence: sequence,
                    bytes: Vec::new(),
                    received: Vec::new(),
                    started: at,
                },
            );
        }
        let pending = self.pending.get_mut(&key)?;
        pending.write(sequence, payload);
        match tls::parse_client_hello(pending.contiguous()) {
            Hello::Incomplete { needed } if needed <= MAX_HELLO_BYTES => None,
            Hello::Named(name) => {
                let _ = self.pending.remove(&key);
                Some(name)
            }
            Hello::Incomplete { .. } | Hello::Unnamed | Hello::NotTls => {
                let _ = self.pending.remove(&key);
                None
            }
        }
    }

    /// Gives up on hellos still incomplete after ten seconds.
    pub fn expire(&mut self, now: UnixNanos) {
        self.pending
            .retain(|_, pending| now < pending.started.saturating_add(HELLO_TIMEOUT));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::monitor::tls::tests::client_hello;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn at(seconds: u64) -> UnixNanos {
        UnixNanos::new(seconds * 1_000_000_000)
    }

    fn endpoints() -> (Endpoint, Endpoint) {
        (
            Endpoint {
                addr: ip("192.168.1.86"),
                port: 51000,
            },
            Endpoint {
                addr: ip("104.16.1.1"),
                port: 443,
            },
        )
    }

    #[test]
    fn a_better_source_wins_until_it_goes_stale() {
        let mut names = NameTable::new(10);
        let addr = ip("104.16.1.1");

        names.learn(addr, "example.com", NameSource::TlsServerName, at(0));
        names.learn(addr, "cdn.example.net", NameSource::Dns, at(60));
        let while_fresh = names.lookup(addr).unwrap().name.clone();
        names.learn(addr, "other.example.org", NameSource::Dns, at(3_601));
        let after_stale = names.lookup(addr).unwrap().name.clone();

        assert_eq!(&*while_fresh, "example.com");
        assert_eq!(&*after_stale, "other.example.org");
    }

    #[test]
    fn names_expire_after_a_day_and_the_table_is_bounded() {
        let mut names = NameTable::new(1);
        names.learn(ip("1.1.1.1"), "one.one.one.one", NameSource::Dns, at(0));
        names.learn(ip("8.8.8.8"), "dns.google", NameSource::Dns, at(0));
        let refused = names.lookup(ip("8.8.8.8")).is_none();

        names.expire(at(86_400));

        assert!(refused);
        assert!(names.lookup(ip("1.1.1.1")).is_none());
    }

    #[test]
    fn a_hello_split_across_reordered_segments_is_reassembled() {
        let (client, server) = endpoints();
        let hello = client_hello(Some("www.example.com"), 1800, false);
        let mut assembler = HelloAssembler::default();
        let base = u32::MAX - 100;
        let second_offset = u32::try_from(1400).unwrap();

        let from_first = assembler.observe(client, server, base, &hello[..1400], at(0));
        let from_retransmit = assembler.observe(client, server, base, &hello[..1400], at(0));
        let from_second = assembler.observe(client, server, base.wrapping_add(second_offset), &hello[1400..], at(0));

        assert_eq!((from_first, from_retransmit), (None, None));
        assert_eq!(from_second.unwrap().name, "www.example.com");
        assert!(assembler.pending.is_empty());
    }

    #[test]
    fn non_tls_streams_are_never_buffered() {
        let (client, server) = endpoints();
        let mut assembler = HelloAssembler::default();

        let name = assembler.observe(client, server, 0, b"GET / HTTP/1.1\r\n", at(0));

        assert_eq!(name, None);
        assert!(assembler.pending.is_empty());
    }

    #[test]
    fn stalled_hellos_are_given_up_on() {
        let (client, server) = endpoints();
        let hello = client_hello(Some("example.com"), 1800, false);
        let mut assembler = HelloAssembler::default();
        let _ = assembler.observe(client, server, 0, &hello[..1000], at(0));

        assembler.expire(at(10));

        assert!(assembler.pending.is_empty());
    }
}
