//! Finds the address the dashboard signs into each mgmt command for the
//! kernel's reports: this host's IPv4 address and Ethernet address on the
//! interface that routes to the kernel.

// getifaddrs(3) has no safe wrapper in std.
#![allow(unsafe_code)]

use sec_core::security::mgmt_auth::OperatorAddr;
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

/// This host's address on the interface the route to `kernel` leaves by.
pub fn reply_address(kernel: SocketAddr) -> io::Result<OperatorAddr> {
    let ip = local_ipv4_towards(kernel)?;
    let mac = mac_of_interface_with(ip)?;
    Ok(OperatorAddr {
        mac,
        ip: ip.octets(),
    })
}

/// The source address the routing table picks for packets to `dest`.
fn local_ipv4_towards(dest: SocketAddr) -> io::Result<Ipv4Addr> {
    let probe = UdpSocket::bind("0.0.0.0:0")?;
    // Connecting a UDP socket only chooses a route; nothing is sent.
    probe.connect(dest)?;
    match probe.local_addr()?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => Err(io::Error::other("the route to the kernel is not IPv4")),
    }
}

fn mac_of_interface_with(ip: Ipv4Addr) -> io::Result<[u8; 6]> {
    let interfaces = InterfaceList::new()?;
    let not_found = || io::Error::other(format!("no interface with a MAC address holds {ip}"));
    let holder = interfaces
        .iter()
        .find(|ifa| ipv4_of(ifa) == Some(ip))
        .ok_or_else(not_found)?;
    // SAFETY: getifaddrs gives every entry a NUL-terminated name that lives
    // as long as the list.
    let name = unsafe { CStr::from_ptr(holder.ifa_name) };
    interfaces
        .iter()
        // SAFETY: as above, every entry's name is a valid C string.
        .filter(|ifa| unsafe { CStr::from_ptr(ifa.ifa_name) } == name)
        .find_map(mac_of)
        .ok_or_else(not_found)
}

fn ipv4_of(ifa: &libc::ifaddrs) -> Option<Ipv4Addr> {
    let addr = ifa.ifa_addr;
    // SAFETY: a non-null ifa_addr points to a sockaddr owned by the list.
    if addr.is_null() || i32::from(unsafe { (*addr).sa_family }) != libc::AF_INET {
        return None;
    }
    // SAFETY: an AF_INET entry's address is a sockaddr_in; read unaligned
    // because a sockaddr pointer only promises sockaddr's alignment.
    let sin = unsafe { addr.cast::<libc::sockaddr_in>().read_unaligned() };
    Some(Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)))
}

fn mac_of(ifa: &libc::ifaddrs) -> Option<[u8; 6]> {
    let addr = ifa.ifa_addr;
    // SAFETY: a non-null ifa_addr points to a sockaddr owned by the list.
    if addr.is_null() || i32::from(unsafe { (*addr).sa_family }) != libc::AF_PACKET {
        return None;
    }
    // SAFETY: an AF_PACKET entry's address is a sockaddr_ll; read unaligned
    // because a sockaddr pointer only promises sockaddr's alignment.
    let ll = unsafe { addr.cast::<libc::sockaddr_ll>().read_unaligned() };
    if ll.sll_halen != 6 {
        return None;
    }
    let a = ll.sll_addr;
    Some([a[0], a[1], a[2], a[3], a[4], a[5]])
}

/// The interface list from getifaddrs, freed on drop.
struct InterfaceList(*mut libc::ifaddrs);

impl InterfaceList {
    fn new() -> io::Result<Self> {
        let mut head = std::ptr::null_mut();
        // SAFETY: getifaddrs only writes a list head through the pointer.
        if unsafe { libc::getifaddrs(&raw mut head) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(head))
    }

    fn iter(&self) -> impl Iterator<Item = &libc::ifaddrs> {
        // SAFETY: the head is null or the first node of a list that lives
        // until `self` is dropped.
        let first = unsafe { self.0.as_ref() };
        // SAFETY: each ifa_next is null or another node of the same list.
        std::iter::successors(first, |ifa| unsafe { ifa.ifa_next.as_ref() })
    }
}

impl Drop for InterfaceList {
    fn drop(&mut self) {
        // SAFETY: the list came from getifaddrs and is freed only here.
        unsafe { libc::freeifaddrs(self.0) };
    }
}

impl std::fmt::Debug for InterfaceList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InterfaceList").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_address_towards_loopback_is_loopbacks_own_address() {
        let kernel = SocketAddr::from(([127, 0, 0, 1], 1337));

        let got = reply_address(kernel).unwrap();

        assert_eq!(
            got,
            OperatorAddr {
                mac: [0; 6],
                ip: [127, 0, 0, 1],
            }
        );
    }
}
