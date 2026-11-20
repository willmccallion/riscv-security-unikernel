//! The legacy (version 1) VirtIO MMIO transport both VirtIO drivers use:
//! finding a device, bringing it up, and the split virtqueue layout.

use core::cell::UnsafeCell;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

/// The VirtIO device types this kernel drives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceId {
    /// A network card.
    Net = 1,
    /// An entropy source.
    Entropy = 4,
}

/// Register offsets from a device's base address.
mod reg {
    pub const MAGIC: usize = 0x000;
    pub const VERSION: usize = 0x004;
    pub const DEVICE_ID: usize = 0x008;
    pub const GUEST_FEATURES: usize = 0x020;
    pub const GUEST_PAGE_SIZE: usize = 0x028;
    pub const QUEUE_SEL: usize = 0x030;
    pub const QUEUE_NUM: usize = 0x038;
    pub const QUEUE_ALIGN: usize = 0x03c;
    pub const QUEUE_PFN: usize = 0x040;
    pub const QUEUE_NOTIFY: usize = 0x050;
    pub const STATUS: usize = 0x070;
}

/// Device status bits, set in this order as setup proceeds.
mod status {
    pub const ACKNOWLEDGE: u32 = 0x01;
    pub const DRIVER: u32 = 0x02;
    pub const FEATURES_OK: u32 = 0x08;
    pub const DRIVER_OK: u32 = 0x04;
}

/// Where QEMU's `virt` board maps its VirtIO MMIO slots, one per page.
const PROBE_START: usize = 0x1000_1000;
const PROBE_END: usize = 0x1000_8000;
const PROBE_STRIDE: usize = 0x1000;
/// "virt" in little-endian ASCII, at offset 0 of every VirtIO device.
const MAGIC: u32 = 0x7472_6976;
/// The legacy interface, which addresses queues by page frame number.
const LEGACY_VERSION: u32 = 1;

/// The descriptor flag marking a buffer the device writes into.
pub const DESC_F_WRITE: u16 = 2;

/// Guest page size and used-ring alignment programmed into every device.
///
/// Legacy VirtIO places the used ring at the next `QUEUE_ALIGN` boundary
/// after the available ring and addresses the queue by `addr / page`.
/// With at most two descriptors everything before the used ring fits in
/// 64 bytes, so a 64-byte page keeps each queue to 128 bytes instead of
/// the two 4 KB pages a 4096-byte page would cost in 64 KB of RAM.
pub const GUEST_PAGE: u32 = 64;

/// Memory the device reads or writes behind the compiler's back, so every
/// access is volatile and none is cached or reordered away.
#[repr(transparent)]
pub struct VolatileCell<T: Copy>(UnsafeCell<T>);

// SAFETY: the kernel runs on one hart, so the only other party touching a
// cell is the device, which volatile accesses account for.
unsafe impl<T: Copy> Sync for VolatileCell<T> {}

impl<T: Copy> VolatileCell<T> {
    /// A cell holding `value`.
    pub const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    /// The value as it is in memory now.
    pub fn get(&self) -> T {
        // SAFETY: the pointer comes from a live `UnsafeCell`, so it is valid
        // and aligned for `T`.
        unsafe { read_volatile(self.0.get()) }
    }

    /// Stores `value` where the device can see it.
    pub fn set(&self, value: T) {
        // SAFETY: as for `get`.
        unsafe { write_volatile(self.0.get(), value) }
    }
}

/// A buffer descriptor.
#[derive(Clone, Copy)]
#[repr(C, align(16))]
pub struct Desc {
    /// The buffer's physical address.
    pub addr: u64,
    /// The buffer's length in bytes.
    pub len: u32,
    /// [`DESC_F_WRITE`] for a buffer the device fills, else 0.
    pub flags: u16,
    /// The next descriptor in a chain; unused, as no buffer is chained.
    pub next: u16,
}

impl Desc {
    const EMPTY: Self = Self {
        addr: 0,
        len: 0,
        flags: 0,
        next: 0,
    };
}

/// The ring the driver offers descriptors on.
#[repr(C)]
pub struct Avail<const N: usize> {
    flags: u16,
    /// Where the driver will put its next entry, wrapping.
    pub idx: VolatileCell<u16>,
    /// Descriptor ids, in the order offered.
    pub ring: [VolatileCell<u16>; N],
    event: u16,
}

/// One buffer the device has finished with.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct UsedElem {
    /// The descriptor id.
    pub id: u32,
    /// How many bytes the device wrote into it.
    pub len: u32,
}

/// The ring the device returns descriptors on; aligned to [`GUEST_PAGE`]
/// so it starts on the page after the available ring.
#[repr(C, align(64))]
pub struct Used<const N: usize> {
    flags: VolatileCell<u16>,
    /// Where the device will put its next entry, wrapping.
    pub idx: VolatileCell<u16>,
    /// Returned buffers, in the order finished.
    pub ring: [VolatileCell<UsedElem>; N],
    event: VolatileCell<u16>,
}

/// A legacy split virtqueue of `N` descriptors.
#[repr(C, align(64))]
pub struct Queue<const N: usize> {
    /// The descriptor table.
    pub desc: [VolatileCell<Desc>; N],
    /// The available ring.
    pub avail: Avail<N>,
    /// The used ring, one page in.
    pub used: Used<N>,
}

impl<const N: usize> Queue<N> {
    /// An empty queue, before any buffer is offered.
    pub const fn new() -> Self {
        Self {
            desc: [const { VolatileCell::new(Desc::EMPTY) }; N],
            avail: Avail {
                flags: 0,
                idx: VolatileCell::new(0),
                ring: [const { VolatileCell::new(0) }; N],
                event: 0,
            },
            used: Used {
                flags: VolatileCell::new(0),
                idx: VolatileCell::new(0),
                ring: [const { VolatileCell::new(UsedElem { id: 0, len: 0 }) }; N],
                event: VolatileCell::new(0),
            },
        }
    }

    /// Compile-time proof that the used ring sits exactly one page in,
    /// where the device looks for it.
    const USED_RING_ON_SECOND_PAGE: () = assert!(
        core::mem::offset_of!(Self, used) == GUEST_PAGE as usize
            && core::mem::align_of::<Self>() == GUEST_PAGE as usize
    );
}

/// The driver's view of a virtqueue: it describes buffers, offers them on
/// the available ring and collects them from the used ring. Only the
/// driver writes the available ring, so it keeps that index itself.
pub struct Ring<const N: usize> {
    queue: &'static Queue<N>,
    next_offer: u16,
    next_used: u16,
}

impl<const N: usize> Ring<N> {
    /// The driver's side of `queue`, before any buffer is offered.
    pub const fn new(queue: &'static Queue<N>) -> Self {
        Self {
            queue,
            next_offer: 0,
            next_used: 0,
        }
    }

    /// Points descriptor `id` at a buffer.
    pub fn describe(&self, id: usize, desc: Desc) {
        self.queue.desc[id].set(desc);
    }

    /// Hands descriptor `id` to the device.
    pub fn offer(&mut self, id: usize) {
        self.queue.avail.ring[usize::from(self.next_offer) % N].set(id as u16);
        // The device must see the entry before the index that publishes it.
        fence(Ordering::SeqCst);
        self.next_offer = self.next_offer.wrapping_add(1);
        self.queue.avail.idx.set(self.next_offer);
    }

    /// The descriptor the next [`Self::offer`] fills, when buffers are
    /// offered in rotation.
    pub fn next_slot(&self) -> usize {
        usize::from(self.next_offer) % N
    }

    /// The next buffer the device has returned, consuming its used entry.
    pub fn next_used(&mut self) -> Option<UsedElem> {
        if self.queue.used.idx.get() == self.next_used {
            return None;
        }
        // Read the entry only after seeing the index that published it.
        fence(Ordering::SeqCst);
        let elem = self.queue.used.ring[usize::from(self.next_used) % N].get();
        self.next_used = self.next_used.wrapping_add(1);
        Some(elem)
    }

    /// How many offered buffers the device has not yet returned.
    pub fn in_flight(&self) -> usize {
        usize::from(self.next_offer.wrapping_sub(self.queue.used.idx.get()))
    }
}

/// A probed device's register block.
#[derive(Debug, Clone, Copy)]
pub struct Mmio {
    base: usize,
}

impl Mmio {
    /// The first legacy device of type `device` in the MMIO window.
    pub fn probe(device: DeviceId) -> Option<Self> {
        let mut base = PROBE_START;
        while base <= PROBE_END {
            let mmio = Self { base };
            if mmio.is_legacy(device) {
                return Some(mmio);
            }
            base += PROBE_STRIDE;
        }
        None
    }

    fn is_legacy(self, device: DeviceId) -> bool {
        self.read(reg::MAGIC) == MAGIC
            && self.read(reg::DEVICE_ID) == device as u32
            && self.read(reg::VERSION) == LEGACY_VERSION
    }

    /// The register block's address.
    pub const fn base(self) -> usize {
        self.base
    }

    /// Resets the device, tells it a driver is here, accepts none of its
    /// optional features, and sets the guest page size; queues go in next.
    pub fn begin_setup(self) {
        self.write(reg::STATUS, 0);
        self.write(reg::STATUS, status::ACKNOWLEDGE | status::DRIVER);
        self.write(reg::GUEST_FEATURES, 0);
        self.write(
            reg::STATUS,
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK,
        );
        self.write(reg::GUEST_PAGE_SIZE, GUEST_PAGE);
    }

    /// Hands the queue at `queue` to the device as virtqueue `index`. Its
    /// address must fit in 32 bits, as all of this kernel's RAM does.
    pub fn install_queue<const N: usize>(self, index: u32, queue: &Queue<N>) {
        let () = Queue::<N>::USED_RING_ON_SECOND_PAGE;
        self.write(reg::QUEUE_SEL, index);
        self.write(reg::QUEUE_NUM, N as u32);
        self.write(reg::QUEUE_ALIGN, GUEST_PAGE);
        self.write(reg::QUEUE_PFN, address_of(queue) / GUEST_PAGE);
    }

    /// Tells the device its queues are ready.
    pub fn finish_setup(self) {
        self.write(
            reg::STATUS,
            status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
        );
    }

    /// Tells the device virtqueue `index` has new available buffers.
    pub fn notify(self, index: u32) {
        // Ring updates must reach memory before the device is told of them.
        fence(Ordering::SeqCst);
        self.write(reg::QUEUE_NOTIFY, index);
    }

    fn read(self, offset: usize) -> u32 {
        // SAFETY: `base` is a slot in the VirtIO MMIO window and `offset` a
        // register inside its 4 KB block, which is always readable.
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    fn write(self, offset: usize, value: u32) {
        // SAFETY: as for `read`; writing a register only affects the
        // device in that slot.
        unsafe { write_volatile((self.base + offset) as *mut u32, value) }
    }
}

/// The physical address of `value`; the kernel runs with paging off, and
/// all of its RAM lies below 4 GB.
pub fn address_of<T: ?Sized>(value: &T) -> u32 {
    core::ptr::from_ref(value).cast::<u8>() as usize as u32
}
