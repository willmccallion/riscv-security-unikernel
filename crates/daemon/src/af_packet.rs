//! Raw packet I/O on a Linux interface through `AF_PACKET`.
//!
//! Receive uses a memory-mapped `TPACKET_V3` ring: the kernel fills
//! blocks of frames and hands each block to userspace whole, so a busy
//! interface costs one `poll` per block rather than one syscall per
//! frame. Transmit uses a plain bound socket that bypasses the qdisc.

#![allow(unsafe_code)]

use anyhow::{Context, Result, bail};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU32, Ordering};

/// Bytes per ring block. The kernel retires a block when it fills or when
/// `BLOCK_TIMEOUT_MS` passes.
const BLOCK_SIZE: u32 = 1 << 20;
/// Blocks in the ring: 64 MiB of receive buffering.
const BLOCK_COUNT: u32 = 64;
/// Upper bound on one frame slot within a block.
const FRAME_SIZE: u32 = 2048;
/// How long a partly filled block waits before going to userspace.
const BLOCK_TIMEOUT_MS: u32 = 10;

/// Opens a raw `AF_PACKET` socket that sees every protocol.
fn packet_socket() -> Result<OwnedFd> {
    let protocol = i32::from((libc::ETH_P_ALL as u16).to_be());
    // SAFETY: socket(2) takes no pointers; the result is checked below.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, protocol) };
    if fd < 0 {
        return Err(io::Error::last_os_error()).context("socket(AF_PACKET) (needs CAP_NET_RAW)");
    }
    // SAFETY: fd is a freshly created descriptor that nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn setsockopt<T>(fd: &OwnedFd, option: libc::c_int, value: &T) -> Result<()> {
    let len = libc::socklen_t::try_from(size_of::<T>()).context("option too large")?;
    // SAFETY: value points to a live T of exactly `len` bytes for the call.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_PACKET,
            option,
            std::ptr::from_ref(value).cast(),
            len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error()).with_context(|| format!("setsockopt({option})"));
    }
    Ok(())
}

fn interface_index(name: &str) -> Result<libc::c_int> {
    let c_name = CString::new(name).context("interface name contains NUL")?;
    // SAFETY: c_name is a valid NUL-terminated string for the call.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        bail!("no interface named {name:?}");
    }
    libc::c_int::try_from(index).context("interface index out of range")
}

fn bind_to(fd: &OwnedFd, ifindex: libc::c_int) -> Result<()> {
    // SAFETY: sockaddr_ll is plain old data; all-zero is a valid value.
    let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as u16;
    addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
    addr.sll_ifindex = ifindex;
    let len = libc::socklen_t::try_from(size_of::<libc::sockaddr_ll>()).context("sockaddr size")?;
    // SAFETY: addr is a live sockaddr_ll of `len` bytes for the call.
    let rc = unsafe {
        libc::bind(fd.as_raw_fd(), std::ptr::from_ref(&addr).cast(), len)
    };
    if rc != 0 {
        return Err(io::Error::last_os_error()).context("bind(AF_PACKET)");
    }
    Ok(())
}

/// Counters the kernel keeps for a receive ring, reset on each read.
#[derive(Debug, Clone, Copy, Default)]
pub struct RingStats {
    /// Frames the kernel delivered to the ring.
    pub packets: u32,
    /// Frames dropped because the ring was full.
    pub drops: u32,
}

/// A `TPACKET_V3` receive ring bound to one interface.
#[derive(Debug)]
pub struct RxRing {
    fd: OwnedFd,
    ring: NonNull<u8>,
    ring_len: usize,
    next_block: u32,
}

impl RxRing {
    /// Opens a receive ring on `interface`. Frames this host sends on the
    /// interface are not delivered back.
    pub fn open(interface: &str) -> Result<Self> {
        let ifindex = interface_index(interface)?;
        let fd = packet_socket()?;
        setsockopt(&fd, libc::PACKET_VERSION, &(libc::tpacket_versions::TPACKET_V3 as libc::c_int))?;
        let req = libc::tpacket_req3 {
            tp_block_size: BLOCK_SIZE,
            tp_block_nr: BLOCK_COUNT,
            tp_frame_size: FRAME_SIZE,
            tp_frame_nr: BLOCK_SIZE / FRAME_SIZE * BLOCK_COUNT,
            tp_retire_blk_tov: BLOCK_TIMEOUT_MS,
            tp_sizeof_priv: 0,
            tp_feature_req_word: 0,
        };
        setsockopt(&fd, libc::PACKET_RX_RING, &req)?;
        setsockopt(&fd, libc::PACKET_IGNORE_OUTGOING, &1 as &libc::c_int)?;

        let ring_len = (BLOCK_SIZE as usize) * (BLOCK_COUNT as usize);
        // SAFETY: maps the ring the kernel just allocated for this socket;
        // the result is checked against MAP_FAILED below.
        let ring = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ring_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd.as_raw_fd(),
                0,
            )
        };
        if ring == libc::MAP_FAILED {
            return Err(io::Error::last_os_error()).context("mmap(PACKET_RX_RING)");
        }
        let ring = NonNull::new(ring.cast::<u8>()).context("mmap returned null")?;
        bind_to(&fd, ifindex)?;
        Ok(Self {
            fd,
            ring,
            ring_len,
            next_block: 0,
        })
    }

    /// Waits up to `timeout_ms` for the next block of frames and passes
    /// each one, mutably, to `handle`. Returns the number of frames seen.
    // Blocks are page-aligned and the kernel aligns each frame header.
    #[allow(clippy::cast_ptr_alignment)]
    pub fn poll(&mut self, timeout_ms: i32, mut handle: impl FnMut(&mut [u8])) -> Result<usize> {
        let block = self.block_status(self.next_block);
        if block.load(Ordering::Acquire) & libc::TP_STATUS_USER == 0 {
            let mut pfd = libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: libc::POLLIN | libc::POLLERR,
                revents: 0,
            };
            // SAFETY: pfd is a single live pollfd for the duration of the call.
            let rc = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    return Ok(0);
                }
                return Err(err).context("poll");
            }
            if block.load(Ordering::Acquire) & libc::TP_STATUS_USER == 0 {
                return Ok(0);
            }
        }

        let base = self.block_base(self.next_block);
        // SAFETY: the block belongs to userspace (TP_STATUS_USER) until we
        // hand it back below, and lies wholly inside the mapped ring.
        let desc = unsafe { &*base.cast::<libc::tpacket_block_desc>() };
        // SAFETY: TPACKET_V3 blocks always carry the bh1 header variant.
        let header = unsafe { &desc.hdr.bh1 };
        let mut offset = header.offset_to_first_pkt as usize;
        let count = header.num_pkts as usize;
        for _ in 0..count {
            // SAFETY: offset comes from the kernel-written block header and
            // points at a tpacket3_hdr inside this block.
            let pkt = unsafe { &*base.add(offset).cast::<libc::tpacket3_hdr>() };
            let frame_start = offset + usize::from(pkt.tp_mac);
            let frame_len = pkt.tp_snaplen as usize;
            if frame_start + frame_len <= BLOCK_SIZE as usize {
                // SAFETY: the frame lies inside the block we own, and no
                // other reference to these bytes exists while handle runs.
                let frame = unsafe { std::slice::from_raw_parts_mut(base.add(frame_start), frame_len) };
                handle(frame);
            }
            offset += pkt.tp_next_offset as usize;
        }

        block.store(libc::TP_STATUS_KERNEL, Ordering::Release);
        self.next_block = (self.next_block + 1) % BLOCK_COUNT;
        Ok(count)
    }

    /// Reads and resets the kernel's counters for this ring.
    pub fn stats(&self) -> Result<RingStats> {
        // SAFETY: tpacket_stats_v3 is plain old data; all-zero is valid.
        let mut stats: libc::tpacket_stats_v3 = unsafe { std::mem::zeroed() };
        let mut len = libc::socklen_t::try_from(size_of::<libc::tpacket_stats_v3>()).context("stats size")?;
        // SAFETY: stats and len are live and sized for the call.
        let rc = unsafe {
            libc::getsockopt(
                self.fd.as_raw_fd(),
                libc::SOL_PACKET,
                libc::PACKET_STATISTICS,
                std::ptr::from_mut(&mut stats).cast(),
                &raw mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error()).context("getsockopt(PACKET_STATISTICS)");
        }
        Ok(RingStats {
            packets: stats.tp_packets,
            drops: stats.tp_drops,
        })
    }

    const fn block_base(&self, block: u32) -> *mut u8 {
        // SAFETY: block < BLOCK_COUNT, so the offset stays inside the ring.
        unsafe { self.ring.as_ptr().add(block as usize * BLOCK_SIZE as usize) }
    }

    /// The block's status word, shared with the kernel.
    // Blocks are page-aligned, so the status word is 4-byte aligned.
    #[allow(clippy::cast_ptr_alignment)]
    const fn block_status(&self, block: u32) -> &AtomicU32 {
        let base = self.block_base(block);
        let offset = std::mem::offset_of!(libc::tpacket_block_desc, hdr)
            + std::mem::offset_of!(libc::tpacket_hdr_v1, block_status);
        // SAFETY: block_status is a 4-byte-aligned u32 inside the mapped
        // block; the kernel and this process access it only atomically.
        unsafe { AtomicU32::from_ptr(base.add(offset).cast::<u32>()) }
    }
}

impl Drop for RxRing {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly the region mapped in `open`; no references
        // into it outlive `self`.
        unsafe {
            let _ = libc::munmap(self.ring.as_ptr().cast(), self.ring_len);
        }
    }
}

/// A socket that transmits raw Ethernet frames on one interface.
#[derive(Debug)]
pub struct TxSocket {
    fd: OwnedFd,
    sent: u64,
    failed: u64,
}

impl TxSocket {
    /// Opens a transmit socket on `interface`.
    pub fn open(interface: &str) -> Result<Self> {
        let ifindex = interface_index(interface)?;
        let fd = packet_socket()?;
        setsockopt(&fd, libc::PACKET_QDISC_BYPASS, &1 as &libc::c_int)?;
        bind_to(&fd, ifindex)?;
        Ok(Self {
            fd,
            sent: 0,
            failed: 0,
        })
    }

    /// Sends one frame; returns whether the kernel accepted it.
    pub fn send(&mut self, frame: &[u8]) -> bool {
        // SAFETY: frame is a live byte slice for the duration of the call.
        let rc = unsafe { libc::send(self.fd.as_raw_fd(), frame.as_ptr().cast(), frame.len(), 0) };
        let ok = usize::try_from(rc).is_ok_and(|n| n == frame.len());
        if ok {
            self.sent += 1;
        } else {
            self.failed += 1;
        }
        ok
    }

    /// Frames sent and frames the kernel refused so far.
    pub const fn counts(&self) -> (u64, u64) {
        (self.sent, self.failed)
    }
}

impl sec_core::net::PacketSink for TxSocket {
    fn send(&mut self, frame: &[u8]) {
        let _ = Self::send(self, frame);
    }
}
