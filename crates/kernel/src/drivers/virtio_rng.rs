//! VirtIO entropy device driver.
//!
//! Probes for a VirtIO 1.0 legacy entropy device on the same MMIO
//! range as the net driver and exposes a single blocking `read_into`
//! call. Used during boot to derive the SYN-cookie secret, CMS seed,
//! and mgmt-auth epoch from real entropy instead of `mcycle`.
//!
//! Sized for one-shot, init-time use: a single descriptor and a small
//! request buffer keep the queue under one page.

use super::virtio_mmio::{DESC_F_WRITE, DeviceId, Mmio, Queue};
use crate::{kprint, kprintln};
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

/// The device's only virtqueue.
const REQUEST_QUEUE: u32 = 0;

const QSIZE: usize = 1;
const RNG_BUF_LEN: usize = 32;

/// Spin budget while waiting for the device to answer a request; QEMU
/// answers within microseconds, and a device that never does should cost
/// entropy, not the boot.
const REPLY_SPINS: u32 = 10_000_000;

/// Receive buffer for entropy bytes. Held outside the queue struct so
/// the queue itself stays compact; the descriptor's `addr` field
/// points at this static.
static mut RNG_BUF: [u8; RNG_BUF_LEN] = [0; RNG_BUF_LEN];

// SAFETY: Queue is an aggregate of integers; an all-zero bit pattern is
// a valid initial state for every field.
static mut RNG_QUEUE: Queue<QSIZE> = unsafe { core::mem::zeroed() };
static mut DEVICE: Option<Mmio> = None;
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
        let Some(mmio) = Mmio::probe(DeviceId::Entropy) else {
            kprintln!("not present");
            return false;
        };
        // SAFETY: DEVICE is only written here, during single-threaded init.
        unsafe { DEVICE = Some(mmio) };
        kprintln!("Found at {:#x}", mmio.base());

        mmio.begin_setup();
        mmio.install_queue(REQUEST_QUEUE, addr_of!(RNG_QUEUE));
        mmio.finish_setup();
        kprintln!("[VirtIO-RNG] Driver OK");
        true
    }

    /// Posts a writable descriptor pointing at `buf`, notifies the
    /// device, and busy-waits for the used ring to advance. Returns
    /// the number of bytes the device wrote, capped at `buf.len()`.
    pub fn read_into(buf: &mut [u8]) -> usize {
        // SAFETY: DEVICE is only written during single-threaded init.
        let Some(mmio) = (unsafe { DEVICE }) else {
            return 0;
        };
        let want = buf.len().min(RNG_BUF_LEN);
        if want == 0 {
            return 0;
        }
        // SAFETY: RNG_QUEUE is a mutable static accessed only from this
        // single-threaded init path. The device reads the descriptor and
        // available ring and writes the used ring, so all of them are
        // accessed volatile, with fences keeping the device's view in order.
        // The descriptor points at RNG_BUF, valid for the life of the static.
        unsafe {
            let q = addr_of_mut!(RNG_QUEUE);
            let desc = addr_of_mut!((*q).desc[0]);
            write_volatile(addr_of_mut!((*desc).addr), addr_of_mut!(RNG_BUF) as u64);
            write_volatile(addr_of_mut!((*desc).len), want as u32);
            write_volatile(addr_of_mut!((*desc).flags), DESC_F_WRITE);
            write_volatile(addr_of_mut!((*desc).next), 0);
            write_volatile(addr_of_mut!((*q).avail.ring[0]), 0);
            fence(Ordering::SeqCst);
            let avail_idx = read_volatile(addr_of!((*q).avail.idx));
            write_volatile(addr_of_mut!((*q).avail.idx), avail_idx.wrapping_add(1));
            fence(Ordering::SeqCst);

            mmio.notify(REQUEST_QUEUE);

            // Bounded busy-wait. QEMU's virtio-rng services a request
            // in microseconds; if the device never replies (broken or
            // absent) we'd rather boot with degraded entropy than hang.
            let mut spins: u32 = 0;
            while read_volatile(addr_of!((*q).used.idx)) == RNG_LAST_USED {
                spins = spins.wrapping_add(1);
                if spins > REPLY_SPINS {
                    return 0;
                }
            }
            fence(Ordering::SeqCst);
            let len = read_volatile(addr_of!((*q).used.ring[0].len)) as usize;
            RNG_LAST_USED = read_volatile(addr_of!((*q).used.idx));
            let n = len.min(want);
            let src = addr_of_mut!(RNG_BUF).cast::<u8>();
            core::ptr::copy_nonoverlapping(src, buf.as_mut_ptr(), n);
            n
        }
    }
}
