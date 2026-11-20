//! VirtIO entropy device driver.
//!
//! Probes for a legacy VirtIO entropy device on the same MMIO range as the
//! net driver and reads from it during boot, to derive the per-boot
//! secrets from real entropy instead of `mcycle`. One descriptor and a
//! small request buffer keep its queue to 128 bytes.

use super::virtio_mmio::{DESC_F_WRITE, Desc, DeviceId, Mmio, Queue, Ring, UsedElem, address_of};
use crate::{kprint, kprintln};
use core::cell::UnsafeCell;
use sec_core::types::TakeOnce;

/// The device's only virtqueue.
const REQUEST_QUEUE: u32 = 0;

/// The most bytes one request asks for.
const RNG_BUF_LEN: usize = 32;

/// Spin budget while waiting for the device to answer a request; QEMU
/// answers within microseconds, and a device that never does should cost
/// entropy, not the boot.
const REPLY_SPINS: u32 = 10_000_000;

/// The buffer the device writes entropy into.
struct RequestBuffer(UnsafeCell<[u8; RNG_BUF_LEN]>);

// SAFETY: the kernel runs on one hart; the buffer is only read by the
// driver after the device has returned it.
unsafe impl Sync for RequestBuffer {}

/// Everything the device reads or writes.
struct DeviceMemory {
    queue: Queue<1>,
    buffer: RequestBuffer,
}

static MEMORY: TakeOnce<DeviceMemory> = TakeOnce::new(DeviceMemory {
    queue: Queue::new(),
    buffer: RequestBuffer(UnsafeCell::new([0; RNG_BUF_LEN])),
});

/// The entropy device.
pub struct VirtioRng {
    mmio: Mmio,
    ring: Ring<1>,
    buffer: &'static RequestBuffer,
}

impl VirtioRng {
    /// Probes for an entropy device and brings it up; `None` if there is
    /// none (real hardware booted without `-device virtio-rng-device`, say),
    /// and the caller falls back to weaker per-boot sources.
    pub fn init() -> Option<Self> {
        kprint!("[VirtIO-RNG] Probing... ");
        let Some(mmio) = Mmio::probe(DeviceId::Entropy) else {
            kprintln!("not present");
            return None;
        };
        let memory: &'static DeviceMemory = MEMORY.take()?;
        kprintln!("Found at {:#x}", mmio.base());

        mmio.begin_setup();
        mmio.install_queue(REQUEST_QUEUE, &memory.queue);
        mmio.finish_setup();
        kprintln!("[VirtIO-RNG] Driver OK");
        Some(Self {
            mmio,
            ring: Ring::new(&memory.queue),
            buffer: &memory.buffer,
        })
    }

    /// Asks the device for up to [`RNG_BUF_LEN`] bytes into `buf` and waits
    /// a bounded time for them; how many it wrote, or `None` if it never
    /// answered.
    pub fn read_into(&mut self, buf: &mut [u8]) -> Option<usize> {
        let want = buf.len().min(RNG_BUF_LEN);
        self.ring.describe(
            0,
            Desc {
                addr: u64::from(address_of(self.buffer)),
                len: want as u32,
                flags: DESC_F_WRITE,
                next: 0,
            },
        );
        self.ring.offer(0);
        self.mmio.notify(REQUEST_QUEUE);
        let reply = self.wait_for_reply()?;
        let written = (reply.len as usize).min(want);
        // SAFETY: the device has returned the buffer, and it is not offered
        // again until the next request.
        let entropy = unsafe { &*self.buffer.0.get() };
        buf.iter_mut()
            .zip(entropy)
            .take(written)
            .for_each(|(dst, &src)| *dst = src);
        Some(written)
    }

    fn wait_for_reply(&mut self) -> Option<UsedElem> {
        for _ in 0..REPLY_SPINS {
            if let Some(reply) = self.ring.next_used() {
                return Some(reply);
            }
        }
        None
    }
}
