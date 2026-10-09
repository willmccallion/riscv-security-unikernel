//! Address prefixes and which side of the local network traffic is on.

use anyhow::{Context, Result, bail};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// An IPv4 or IPv6 network: an address with only its first `len` bits
/// kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpPrefix {
    network: IpAddr,
    len: u8,
}

impl IpPrefix {
    /// The `len`-bit prefix containing `addr`, or `None` if `len` is longer
    /// than the address.
    pub fn new(addr: IpAddr, len: u8) -> Option<Self> {
        let network = match addr {
            IpAddr::V4(v4) => IpAddr::V4(mask_v4(u32::from(v4), len)?.into()),
            IpAddr::V6(v6) => IpAddr::V6(mask_v6(u128::from(v6), len)?.into()),
        };
        Some(Self { network, len })
    }

    /// Whether `addr` lies inside this prefix.
    pub fn contains(&self, addr: IpAddr) -> bool {
        Self::new(addr, self.len).is_some_and(|p| p.network == self.network)
    }
}

impl fmt::Display for IpPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.len)
    }
}

impl FromStr for IpPrefix {
    type Err = anyhow::Error;

    /// Parses `address/len`, or a bare address as a single-host prefix.
    fn from_str(text: &str) -> Result<Self> {
        let (addr, len) = match text.split_once('/') {
            Some((addr, len)) => (addr, Some(len)),
            None => (text, None),
        };
        let addr: IpAddr = addr.parse().with_context(|| format!("bad address in {text:?}"))?;
        let host_len = if addr.is_ipv4() { 32 } else { 128 };
        let len = match len {
            Some(len) => len.parse().with_context(|| format!("bad prefix length in {text:?}"))?,
            None => host_len,
        };
        let Some(prefix) = Self::new(addr, len) else {
            bail!("prefix length {len} is longer than the address in {text:?}");
        };
        Ok(prefix)
    }
}

/// `addr` with only its first `len` bits kept; `None` if `len > 32`.
const fn mask_v4(addr: u32, len: u8) -> Option<u32> {
    if len > 32 {
        return None;
    }
    match u32::MAX.checked_shl(32 - len as u32) {
        Some(mask) => Some(addr & mask),
        None => Some(0),
    }
}

/// `addr` with only its first `len` bits kept; `None` if `len > 128`.
const fn mask_v6(addr: u128, len: u8) -> Option<u128> {
    if len > 128 {
        return None;
    }
    match u128::MAX.checked_shl(128 - len as u32) {
        Some(mask) => Some(addr & mask),
        None => Some(0),
    }
}

/// Which way a packet crosses the boundary of the local networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// From outside to a local address.
    Inbound,
    /// From a local address to outside.
    Outbound,
    /// Between two local addresses.
    Internal,
    /// Between two outside addresses, as a router or mirror port sees.
    Transit,
}

/// The networks considered local: the monitored host's own, plus any the
/// configuration adds, such as the rest of a home network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalNetworks {
    prefixes: Vec<IpPrefix>,
}

impl LocalNetworks {
    /// Local networks made of `prefixes`, each listed once; an interface
    /// with several addresses in one network yields it several times.
    pub fn new(prefixes: Vec<IpPrefix>) -> Self {
        let mut unique: Vec<IpPrefix> = Vec::with_capacity(prefixes.len());
        for prefix in prefixes {
            if !unique.contains(&prefix) {
                unique.push(prefix);
            }
        }
        Self { prefixes: unique }
    }

    /// The prefixes, in the order given.
    pub fn prefixes(&self) -> &[IpPrefix] {
        &self.prefixes
    }

    /// Whether `addr` is local: inside a local prefix, or loopback,
    /// link-local, multicast, broadcast or unspecified (the source of DHCP
    /// and neighbour discovery), none of which leave the local network.
    pub fn contains(&self, addr: IpAddr) -> bool {
        never_leaves_local_network(addr) || self.prefixes.iter().any(|p| p.contains(addr))
    }

    /// Which way a packet from `src` to `dst` goes.
    pub fn direction(&self, src: IpAddr, dst: IpAddr) -> Direction {
        match (self.contains(src), self.contains(dst)) {
            (false, true) => Direction::Inbound,
            (true, false) => Direction::Outbound,
            (true, true) => Direction::Internal,
            (false, false) => Direction::Transit,
        }
    }
}

const fn never_leaves_local_network(addr: IpAddr) -> bool {
    addr.is_loopback()
        || addr.is_multicast()
        || addr.is_unspecified()
        || match addr {
            IpAddr::V4(v4) => v4.is_link_local() || v4.is_broadcast(),
            IpAddr::V6(v6) => v6.is_unicast_link_local(),
        }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn prefixes_keep_only_network_bits_for_both_families() {
        let v4: IpPrefix = "192.168.1.86/24".parse().unwrap();
        let v6: IpPrefix = "2001:56a:e9c4:700:ca96:2774:33fa:b1f2/64".parse().unwrap();

        assert_eq!(v4.to_string(), "192.168.1.0/24");
        assert_eq!(v6.to_string(), "2001:56a:e9c4:700::/64");
        assert!(v6.contains(ip("2001:56a:e9c4:700::1")));
        assert!(!v6.contains(ip("2001:56a:e9c4:701::1")));
        assert!(!v4.contains(ip("::ffff:192.168.1.5")), "families never match");
    }

    #[test]
    fn edge_lengths_parse_and_overlong_ones_are_rejected() {
        assert!("0.0.0.0/0".parse::<IpPrefix>().unwrap().contains(ip("8.8.8.8")));
        assert_eq!("10.0.0.1".parse::<IpPrefix>().unwrap().to_string(), "10.0.0.1/32");
        assert!("10.0.0.0/33".parse::<IpPrefix>().is_err());
        assert!("::/129".parse::<IpPrefix>().is_err());
        assert!("10.0.0.0/x".parse::<IpPrefix>().is_err());
    }

    #[test]
    fn direction_follows_which_ends_are_local() {
        let local = LocalNetworks::new(vec!["192.168.1.0/24".parse().unwrap(), "fd00::/8".parse().unwrap()]);

        assert_eq!(local.direction(ip("1.1.1.1"), ip("192.168.1.86")), Direction::Inbound);
        assert_eq!(local.direction(ip("fd00::5"), ip("2606:4700::1")), Direction::Outbound);
        assert_eq!(local.direction(ip("192.168.1.2"), ip("192.168.1.86")), Direction::Internal);
        assert_eq!(local.direction(ip("8.8.8.8"), ip("1.1.1.1")), Direction::Transit);
    }

    #[test]
    fn repeated_prefixes_are_listed_once() {
        let stable: IpPrefix = "2001:db8:1::5/64".parse().unwrap();
        let temporary: IpPrefix = "2001:db8:1::abcd/64".parse().unwrap();

        let local = LocalNetworks::new(vec![stable, temporary, stable]);

        assert_eq!(local.prefixes(), [stable]);
    }

    #[test]
    fn link_scoped_destinations_stay_local() {
        let local = LocalNetworks::new(vec!["192.168.1.0/24".parse().unwrap()]);

        assert_eq!(local.direction(ip("192.168.1.9"), ip("224.0.0.251")), Direction::Internal);
        assert_eq!(local.direction(ip("192.168.1.9"), ip("255.255.255.255")), Direction::Internal);
        assert_eq!(local.direction(ip("fe80::1"), ip("ff02::fb")), Direction::Internal);
        assert_eq!(local.direction(ip("0.0.0.0"), ip("255.255.255.255")), Direction::Internal);
        assert_eq!(local.direction(ip("::"), ip("ff02::1:ff00:2")), Direction::Internal);
        assert_eq!(local.direction(ip("::1"), ip("::1")), Direction::Internal);
        assert_eq!(local.direction(ip("127.0.0.1"), ip("127.0.0.53")), Direction::Internal);
    }
}
