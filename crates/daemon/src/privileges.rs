//! Giving up privileges once the capture socket is open.
//!
//! Capturing needs `CAP_NET_RAW` only to create the socket; parsing what
//! arrives on it needs nothing. Dropping everything afterwards means a
//! bug in a parser fed by hostile traffic runs with no privileges.

#![allow(unsafe_code)]

use anyhow::{Context, Result, bail};
use std::io;

/// `_LINUX_CAPABILITY_VERSION_3`: 64-bit capability sets in two words.
const CAPABILITY_VERSION_3: u32 = 0x2008_0522;

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// Drops to the invoking user if started as root through `sudo`, clears
/// every capability and forbids regaining any, then confirms none remain.
///
/// Refuses to continue as the host's root without `sudo`, since there
/// would be no unprivileged user to become; grant the binary
/// `cap_net_raw` instead. Root inside a user namespace that maps it to an
/// ordinary user, as `unshare -r` and rootless containers do, is not the
/// host's root and only needs its capabilities cleared.
/// Capability sets belong to threads, so call this before starting any.
pub fn drop_all() -> Result<()> {
    // SAFETY: geteuid takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } == 0 && root_is_host_root()? {
        become_sudo_user()?;
    }
    clear_capabilities()?;
    // SAFETY: PR_SET_NO_NEW_PRIVS takes integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        bail!("prctl(PR_SET_NO_NEW_PRIVS): {}", io::Error::last_os_error());
    }
    let effective = effective_capabilities()?;
    if effective != 0 {
        bail!("capabilities remain after dropping them: CapEff = {effective:#x}");
    }
    Ok(())
}

/// Whether uid 0 in this process's user namespace is uid 0 on the host.
fn root_is_host_root() -> Result<bool> {
    let map = std::fs::read_to_string("/proc/self/uid_map").context("read /proc/self/uid_map")?;
    Ok(maps_root_to_host_root(&map))
}

/// Whether a `uid_map` maps inside uid 0 to outside uid 0. Each line is
/// `inside outside count`.
fn maps_root_to_host_root(uid_map: &str) -> bool {
    uid_map.lines().any(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        matches!(fields.as_slice(), ["0", "0", _])
    })
}

fn become_sudo_user() -> Result<()> {
    let id = |name: &str| -> Result<u32> {
        std::env::var(name)
            .with_context(|| format!("running as root without {name}; use `setcap cap_net_raw+ep` instead of root"))?
            .parse()
            .with_context(|| format!("{name} is not a number"))
    };
    let (uid, gid) = (id("SUDO_UID")?, id("SUDO_GID")?);
    if uid == 0 {
        bail!("sudo was invoked by root; run as an ordinary user with `setcap cap_net_raw+ep`");
    }
    // SAFETY: setgroups with a zero count reads no memory.
    if unsafe { libc::setgroups(0, std::ptr::null()) } != 0 {
        bail!("setgroups: {}", io::Error::last_os_error());
    }
    // SAFETY: setgid takes an integer argument only.
    if unsafe { libc::setgid(gid) } != 0 {
        bail!("setgid({gid}): {}", io::Error::last_os_error());
    }
    // SAFETY: setuid takes an integer argument only.
    if unsafe { libc::setuid(uid) } != 0 {
        bail!("setuid({uid}): {}", io::Error::last_os_error());
    }
    Ok(())
}

fn clear_capabilities() -> Result<()> {
    // SAFETY: PR_CAP_AMBIENT_CLEAR_ALL takes integer arguments only.
    if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) } != 0 {
        bail!("prctl(PR_CAP_AMBIENT_CLEAR_ALL): {}", io::Error::last_os_error());
    }
    let header = CapHeader {
        version: CAPABILITY_VERSION_3,
        pid: 0,
    };
    let empty = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    // SAFETY: header and both data words are live, correctly laid out
    // structures for a version-3 capset call on this thread.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &raw const header, empty.as_ptr()) };
    if rc != 0 {
        bail!("capset: {}", io::Error::last_os_error());
    }
    Ok(())
}

/// The effective capability set, from `/proc/self/status`.
fn effective_capabilities() -> Result<u64> {
    let status = std::fs::read_to_string("/proc/self/status").context("read /proc/self/status")?;
    let hex = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:"))
        .context("no CapEff line in /proc/self/status")?;
    u64::from_str_radix(hex.trim(), 16).context("CapEff is not hexadecimal")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_initial_namespace_maps_root_to_host_root() {
        assert!(maps_root_to_host_root("         0          0 4294967295\n"));
    }

    #[test]
    fn a_user_namespace_root_is_an_ordinary_host_user() {
        assert!(!maps_root_to_host_root("         0       1000          1\n"));
        assert!(!maps_root_to_host_root(""));
    }
}
