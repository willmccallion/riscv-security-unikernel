//! VirtIO network device driver.
//!
//! Drives a legacy VirtIO network card through two virtqueues: one the
//! device fills with received frames, one it sends frames from. The rings
//! and buffers live in a static the driver takes once at init, so nothing
//! else can reach memory the device is using.

use super::virtio_mmio::{DESC_F_WRITE, Desc, DeviceId, Mmio, Queue, Ring, address_of};
use crate::{kprint, kprintln};
use core::cell::UnsafeCell;
use sec_core::net::PacketSink;
use sec_core::types::TakeOnce;

/// The virtqueue the device delivers received frames on.
const RX_QUEUE: u32 = 0;

/// The virtqueue the device sends frames from.
const TX_QUEUE: u32 = 1;

/// Number of descriptors in each queue.
const QUEUE_SIZE: usize = 2;

/// Size of VirtIO network header in bytes.
const NET_HDR_SIZE: usize = 10;

/// Maximum buffer size for packet storage.
const BUF_SIZE: usize = 1536;

/// Spin budget while waiting for the device to release a TX descriptor
/// before the frame is dropped.
const TX_RECLAIM_SPINS: u32 = 1_000_000;

/// A packet buffer the device reads from or writes into.
struct Buffer(UnsafeCell<[u8; BUF_SIZE]>);

// SAFETY: the kernel runs on one hart; a buffer is only touched by the
// driver while the device does not own it.
unsafe impl Sync for Buffer {}

impl Buffer {
    const fn new() -> Self {
        Self(UnsafeCell::new([0; BUF_SIZE]))
    }

    fn address(&self) -> u64 {
        u64::from(address_of(self))
    }
}

/// Everything the device reads or writes.
struct DeviceMemory {
    rx_ring: Queue<QUEUE_SIZE>,
    tx_ring: Queue<QUEUE_SIZE>,
    rx_buffers: [Buffer; QUEUE_SIZE],
    tx_buffers: [Buffer; QUEUE_SIZE],
}

static MEMORY: TakeOnce<DeviceMemory> = TakeOnce::new(DeviceMemory {
    rx_ring: Queue::new(),
    tx_ring: Queue::new(),
    rx_buffers: [const { Buffer::new() }; QUEUE_SIZE],
    tx_buffers: [const { Buffer::new() }; QUEUE_SIZE],
});

/// Why the network card could not be brought up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitError {
    /// No legacy VirtIO network device answered the probe.
    NotFound,
    /// The driver was already brought up once.
    AlreadyRunning,
}

/// The network card, split into its receive and transmit halves so a
/// received frame can be answered while it is still borrowed.
pub struct VirtioNet {
    /// Received frames.
    pub rx: Receiver,
    /// Frames to send.
    pub tx: Transmitter,
}

impl VirtioNet {
    /// Probes for the card, offers it every receive buffer and starts it.
    ///
    /// # Errors
    ///
    /// [`InitError`] if there is no card or the driver already owns it.
    pub fn init() -> Result<Self, InitError> {
        kprint!("[VirtIO] Probing... ");
        let mmio = Mmio::probe(DeviceId::Net).ok_or(InitError::NotFound)?;
        let memory: &'static DeviceMemory = MEMORY.take().ok_or(InitError::AlreadyRunning)?;
        kprintln!("Found at {:#x}", mmio.base());

        mmio.begin_setup();
        let rx = Receiver::new(mmio, memory);
        mmio.install_queue(RX_QUEUE, &memory.rx_ring);
        mmio.install_queue(TX_QUEUE, &memory.tx_ring);
        mmio.finish_setup();
        kprintln!("[VirtIO] Driver OK");
        Ok(Self {
            rx,
            tx: Transmitter::new(mmio, memory),
        })
    }

    /// Tells the device to look at both queues: for receive buffers given
    /// back and for frames to send.
    pub fn flush(&self) {
        self.rx.mmio.notify(RX_QUEUE);
        self.tx.mmio.notify(TX_QUEUE);
    }
}

/// The receive half: buffers the device fills with incoming frames.
pub struct Receiver {
    mmio: Mmio,
    ring: Ring<QUEUE_SIZE>,
    buffers: &'static [Buffer; QUEUE_SIZE],
}

impl Receiver {
    /// Describes every receive buffer to the device and offers them all.
    fn new(mmio: Mmio, memory: &'static DeviceMemory) -> Self {
        let mut ring = Ring::new(&memory.rx_ring);
        for (id, buffer) in memory.rx_buffers.iter().enumerate() {
            ring.describe(
                id,
                Desc {
                    addr: buffer.address(),
                    len: BUF_SIZE as u32,
                    flags: DESC_F_WRITE,
                    next: 0,
                },
            );
            ring.offer(id);
        }
        Self {
            mmio,
            ring,
            buffers: &memory.rx_buffers,
        }
    }

    /// Lends the next received frame to `handle`, then gives its buffer
    /// back to the device.
    ///
    /// Returns `None` if no frame is waiting or the device returned one with
    /// no usable frame, which is dropped. The frame cannot outlive `handle`,
    /// so its buffer is never in use while the device owns it again.
    pub fn receive<R>(&mut self, handle: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
        let used = self.ring.next_used()?;
        let id = used.id as usize;
        // An id we never posted has no buffer to hand back.
        let buffer = self.buffers.get(id)?;
        // SAFETY: the device has returned buffer `id`, and it is not offered
        // again until below, so nothing else touches it while `handle` runs.
        let bytes = unsafe { &mut *buffer.0.get() };
        // A runt (header only) or a length past the end of our buffer
        // carries no usable frame.
        let result = bytes
            .get_mut(NET_HDR_SIZE..used.len as usize)
            .filter(|frame| !frame.is_empty())
            .map(handle);
        self.ring.offer(id);
        result
    }
}

/// The transmit half, through which the engine's replies, alerts and
/// telemetry leave.
pub struct Transmitter {
    mmio: Mmio,
    ring: Ring<QUEUE_SIZE>,
    buffers: &'static [Buffer; QUEUE_SIZE],
}

impl Transmitter {
    const fn new(mmio: Mmio, memory: &'static DeviceMemory) -> Self {
        Self {
            mmio,
            ring: Ring::new(&memory.tx_ring),
            buffers: &memory.tx_buffers,
        }
    }

    /// Returns once the device has released a TX descriptor, kicking it
    /// first if the ring is full. Returns `false` if it never does, in
    /// which case the caller drops the frame rather than overwrite a
    /// buffer the device still owns.
    fn wait_for_free_slot(&self) -> bool {
        if self.ring.in_flight() < QUEUE_SIZE {
            return true;
        }
        self.mmio.notify(TX_QUEUE);
        for _ in 0..TX_RECLAIM_SPINS {
            if self.ring.in_flight() < QUEUE_SIZE {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }
}

impl PacketSink for Transmitter {
    /// Copies `frame` behind a zeroed VirtIO net header into the next free
    /// buffer and offers it; the device sends it on the next
    /// [`VirtioNet::flush`]. Frames too big for a buffer, or sent while the
    /// device holds every buffer, are dropped.
    fn send(&mut self, frame: &[u8]) {
        if frame.len() > BUF_SIZE - NET_HDR_SIZE || !self.wait_for_free_slot() {
            return;
        }
        let id = self.ring.next_slot();
        let buffer = &self.buffers[id];
        // SAFETY: fewer than QUEUE_SIZE buffers are in flight and they are
        // offered in order, so the device has returned buffer `id`.
        let (header, body) = unsafe { &mut *buffer.0.get() }.split_at_mut(NET_HDR_SIZE);
        header.fill(0);
        body.iter_mut()
            .zip(frame)
            .for_each(|(dst, &src)| *dst = src);
        self.ring.describe(
            id,
            Desc {
                addr: buffer.address(),
                len: (NET_HDR_SIZE + frame.len()) as u32,
                flags: 0,
                next: 0,
            },
        );
        self.ring.offer(id);
    }
}
