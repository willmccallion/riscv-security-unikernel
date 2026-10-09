//! The addresses assigned to a network interface.

#![allow(unsafe_code)]

use crate::monitor::net::IpPrefix;
use anyhow::{Result, bail};
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The networks `interface`'s addresses belong to, IPv4 and IPv6, from
/// `getifaddrs(3)`.
pub fn interface_networks(interface: &str) -> Result<Vec<IpPrefix>> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: list is a live out-pointer; on success it owns a linked list
    // that freeifaddrs releases below.
    if unsafe { libc::getifaddrs(&raw mut list) } != 0 {
        bail!("getifaddrs: {}", io::Error::last_os_error());
    }
    let mut networks = Vec::new();
    let mut entry = list;
    while !entry.is_null() {
        // SAFETY: entry is a node of the list getifaddrs returned, which
        // stays valid until freeifaddrs.
        let ifa = unsafe { &*entry };
        entry = ifa.ifa_next;
        // SAFETY: ifa_name is a NUL-terminated string owned by the list.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) };
        if name.to_bytes() != interface.as_bytes() {
            continue;
        }
        // SAFETY: address and netmask, when non-null, point at sockaddrs
        // of the family the address declares, owned by the list.
        if let Some(network) = unsafe { network_of(ifa.ifa_addr, ifa.ifa_netmask) } {
            networks.push(network);
        }
    }
    // SAFETY: list came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(list) };
    Ok(networks)
}

/// The prefix an address and netmask describe; `None` for non-IP
/// families or missing fields.
///
/// # Safety
/// Each pointer must be null or point at a live `sockaddr` whose family
/// field matches the structure behind it.
unsafe fn network_of(addr: *const libc::sockaddr, mask: *const libc::sockaddr) -> Option<IpPrefix> {
    if addr.is_null() || mask.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees addr points at a live sockaddr.
    let family = i32::from(unsafe { (*addr).sa_family });
    match family {
        libc::AF_INET => {
            // SAFETY: an AF_INET sockaddr is a sockaddr_in.
            let (a, m) = unsafe { (&*addr.cast::<libc::sockaddr_in>(), &*mask.cast::<libc::sockaddr_in>()) };
            let ip = Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr));
            let len = u32::from_be(m.sin_addr.s_addr).leading_ones();
            IpPrefix::new(IpAddr::V4(ip), u8::try_from(len).ok()?)
        }
        libc::AF_INET6 => {
            // SAFETY: an AF_INET6 sockaddr is a sockaddr_in6.
            let (a, m) = unsafe { (&*addr.cast::<libc::sockaddr_in6>(), &*mask.cast::<libc::sockaddr_in6>()) };
            let ip = Ipv6Addr::from(a.sin6_addr.s6_addr);
            let len = u128::from_be_bytes(m.sin6_addr.s6_addr).leading_ones();
            IpPrefix::new(IpAddr::V6(ip), u8::try_from(len).ok()?)
        }
        _ => None,
    }
}
