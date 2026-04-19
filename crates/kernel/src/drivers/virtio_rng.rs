//! VirtIO entropy device driver.
//!
//! Probes for a VirtIO 1.0 legacy entropy device on the same MMIO
//! range as the net driver and exposes a single blocking `read_into`
//! call. Used during boot to derive the SYN-cookie secret, CMS seed,
//! and mgmt-auth epoch from real entropy instead of `mcycle`.
//!
//! Sized for one-shot, init-time use: a single descriptor and a small
//! request buffer keep the queue under one page.

use crate::{kprint, kprintln};
use core::ptr::{addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

const VIRTIO_START: usize = 0x1000_1000;
const VIRTIO_END: usize = 0x1000_8000;
const VIRTIO_MAGIC: u32 = 0x7472_6976;
const DEVICE_ID_ENTROPY: u32 = 4;
const DEVICE_VERSION_1: u32 = 1;

const STATUS: usize = 0x070;
const QUEUE_SEL: usize = 0x030;
const QUEUE_NUM: usize = 0x038;
const QUEUE_ALIGN: usize = 0x03c;
const QUEUE_PFN: usize = 0x040;
const QUEUE_NOTIFY: usize = 0x050;
const GUEST_PAGE_SIZE: usize = 0x028;
const GUEST_FEATURES: usize = 0x020;

const QSIZE: usize = 1;
const RNG_BUF_LEN: usize = 32;

/// Per-device guest page size (also the queue alignment). Legacy
/// `QUEUE_PFN` is `addr / GUEST_PAGE`, so the queue struct must align
/// to this value. A 64-byte page is the smallest power of 2 that fits
/// the desc + avail + used layout for `QSIZE=1` while keeping the
/// queue under 128 bytes — the kernel only has 64 KB of RAM and a
/// full 4 KB queue would not fit.
const GUEST_PAGE: u32 = 64;

/// Descriptor flag indicating the device may write the buffer.
const DESC_F_WRITE: u16 = 2;

#[repr(C, align(16))]
struct Desc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, align(2))]
struct Avail {
    flags: u16,
    idx: u16,
    ring: [u16; QSIZE],
    event: u16,
}

#[repr(C, align(4))]
struct UsedElem {
    id: u32,
    len: u32,
}

#[repr(C, align(4))]
struct Used {
    flags: u16,
    idx: u16,
    ring: [UsedElem; QSIZE],
    event: u16,
}

/// Layout: `desc` + `avail` + padding so `used` sits at offset 64
/// (matching `QUEUE_ALIGN` written into the device). Aligning the
/// struct to 64 keeps it within one cache line and lets `QUEUE_PFN =
/// addr / GUEST_PAGE` program a valid address.
#[repr(C, align(64))]
struct RngQueue {
    desc: [Desc; QSIZE],
    avail: Avail,
    _pad: [u8; 64 - 16 - 8],
    used: Used,
}

/// Receive buffer for entropy bytes. Held outside the queue struct so
/// the queue itself stays compact; the descriptor's `addr` field
/// points at this static.
static mut RNG_BUF: [u8; RNG_BUF_LEN] = [0; RNG_BUF_LEN];

// SAFETY: RngQueue is an aggregate of integers; an all-zero bit
// pattern is a valid initial state for every field.
static mut RNG_QUEUE: RngQueue = unsafe { core::mem::zeroed() };
static mut RNG_BASE: usize = 0;
static mut RNG_LAST_USED: u16 = 0;

/// VirtIO entropy device handle.
pub struct VirtioRng;

impl VirtioRng {
    /// Probes the VirtIO MMIO range for an entropy device and brings
    /// it up. Returns `false` if no entropy device is attached (e.g.
    /// real hardware booted without `-device virtio-rng-device`), in
    /// which case the caller is expected to fall back to a weaker
    /// per-boot source.
    pub fn init() -> bool {
        kprint!("[VirtIO-RNG] Probing... ");
        let mut addr = VIRTIO_START;
        let mut found = 0usize;
        while addr <= VIRTIO_END {
            // SAFETY: Addresses in the VIRTIO_START..=VIRTIO_END range
            // are valid MMIO addresses on this platform.
            unsafe {
                if read_volatile(addr as *const u32) == VIRTIO_MAGIC
                    && read_volatile((addr + 8) as *const u32) == DEVICE_ID_ENTROPY
                    && read_volatile((addr + 4) as *const u32) == DEVICE_VERSION_1
                {
                    found = addr;
                    break;
                }
            }
            addr += 0x1000;
        }
        if found == 0 {
            kprintln!("not present");
            return false;
        }
        // SAFETY: RNG_BASE is a mutable static only written here during
        // single-threaded init.
        unsafe {
            RNG_BASE = found;
        }
        kprintln!("Found at {:#x}", found);

        Self::reg_write(STATUS, 0);
        Self::reg_write(STATUS, 0x01 | 0x02);
        Self::reg_write(GUEST_FEATURES, 0);
        Self::reg_write(STATUS, 0x01 | 0x02 | 0x08);

        Self::reg_write(GUEST_PAGE_SIZE, GUEST_PAGE);
        Self::reg_write(QUEUE_SEL, 0);
        Self::reg_write(QUEUE_NUM, QSIZE as u32);
        Self::reg_write(QUEUE_ALIGN, GUEST_PAGE);
        // RNG_QUEUE is GUEST_PAGE-aligned; its address fits in u32
        // because all kernel RAM lives in the low 64 KB above
        // 0x8000_0000 — well within u32 range.
        let pfn = (addr_of_mut!(RNG_QUEUE) as u32) / GUEST_PAGE;
        Self::reg_write(QUEUE_PFN, pfn);

        Self::reg_write(STATUS, 0x01 | 0x02 | 0x08 | 0x04);
        kprintln!("[VirtIO-RNG] Driver OK");
        true
    }

    /// Posts a writable descriptor pointing at `buf`, notifies the
    /// device, and busy-waits for the used ring to advance. Returns
    /// the number of bytes the device wrote, capped at `buf.len()`.
    pub fn read_into(buf: &mut [u8]) -> usize {
        // SAFETY: RNG_BASE is set non-zero only after a successful init().
        if unsafe { RNG_BASE } == 0 {
            return 0;
        }
        let want = buf.len().min(RNG_BUF_LEN);
        if want == 0 {
            return 0;
        }
        // SAFETY: RNG_QUEUE is a mutable static accessed only from this
        // single-threaded init path. Volatile writes + a memory fence
        // ensure the device sees the descriptor and avail-index update
        // in order. The descriptor address points into the queue's own
        // `buf`, valid for the lifetime of the static.
        let written = unsafe {
            let q = addr_of_mut!(RNG_QUEUE);
            (*q).desc[0].addr = addr_of_mut!(RNG_BUF) as u64;
            (*q).desc[0].len = want as u32;
            (*q).desc[0].flags = DESC_F_WRITE;
            (*q).desc[0].next = 0;
            (*q).avail.ring[0] = 0;
            fence(Ordering::SeqCst);
            (*q).avail.idx = (*q).avail.idx.wrapping_add(1);
            fence(Ordering::SeqCst);

            write_volatile((RNG_BASE + QUEUE_NOTIFY) as *mut u32, 0);

            // Bounded busy-wait. QEMU's virtio-rng services a request
            // in microseconds; if the device never replies (broken or
            // absent) we'd rather boot with degraded entropy than hang.
            let mut spins: u32 = 0;
            while read_volatile(addr_of_mut!((*q).used.idx)) == RNG_LAST_USED {
                spins = spins.wrapping_add(1);
                if spins > 10_000_000 {
                    return 0;
                }
            }
            fence(Ordering::SeqCst);
            let len = (*q).used.ring[0].len as usize;
            RNG_LAST_USED = (*q).used.idx;
            let n = len.min(want);
            let src = addr_of_mut!(RNG_BUF).cast::<u8>();
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), n);
            n
        };
        written
    }

    fn reg_write(offset: usize, val: u32) {
        // SAFETY: RNG_BASE is a valid VirtIO MMIO base address (set by
        // init() after probe). Offsets are from the VirtIO 1.0 legacy
        // spec.
        unsafe { write_volatile((RNG_BASE + offset) as *mut u32, val) }
    }
}
