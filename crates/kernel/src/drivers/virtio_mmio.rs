//! The legacy (version 1) VirtIO MMIO transport both VirtIO drivers use:
//! finding a device, bringing it up, and the split virtqueue layout.

use core::ptr::{read_volatile, write_volatile};

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

/// A buffer descriptor.
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

/// The ring the driver offers descriptors on.
#[repr(C)]
pub struct Avail<const N: usize> {
    /// Unused; the driver asks for every interrupt it does not take.
    pub flags: u16,
    /// Where the driver will put its next entry, wrapping.
    pub idx: u16,
    /// Descriptor ids, in the order offered.
    pub ring: [u16; N],
    /// Unused without the event-index feature.
    pub event: u16,
}

/// One buffer the device has finished with.
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
    /// Unused by this driver.
    pub flags: u16,
    /// Where the device will put its next entry, wrapping.
    pub idx: u16,
    /// Returned buffers, in the order finished.
    pub ring: [UsedElem; N],
    /// Unused without the event-index feature.
    pub event: u16,
}

/// A legacy split virtqueue of `N` descriptors.
#[repr(C, align(64))]
pub struct Queue<const N: usize> {
    /// The descriptor table.
    pub desc: [Desc; N],
    /// The available ring.
    pub avail: Avail<N>,
    /// The used ring, one page in.
    pub used: Used<N>,
}

impl<const N: usize> Queue<N> {
    /// Compile-time proof that the used ring sits exactly one page in,
    /// where the device looks for it.
    const USED_RING_ON_SECOND_PAGE: () = assert!(
        core::mem::offset_of!(Self, used) == GUEST_PAGE as usize
            && core::mem::align_of::<Self>() == GUEST_PAGE as usize
    );
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
    pub fn install_queue<const N: usize>(self, index: u32, queue: *const Queue<N>) {
        let () = Queue::<N>::USED_RING_ON_SECOND_PAGE;
        self.write(reg::QUEUE_SEL, index);
        self.write(reg::QUEUE_NUM, N as u32);
        self.write(reg::QUEUE_ALIGN, GUEST_PAGE);
        self.write(reg::QUEUE_PFN, queue as u32 / GUEST_PAGE);
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
