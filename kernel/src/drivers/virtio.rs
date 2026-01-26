//! VirtIO network device driver.
//!
//! Implements the VirtIO 1.0 legacy interface for network device access.
//! This driver manages receive and transmit queues, handles packet
//! buffers, and provides a simple interface for sending and receiving
//! Ethernet frames.

use crate::{kprint, kprintln};
use core::ptr::{addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

/// Starting address for VirtIO device probe.
const VIRTIO_START: usize = 0x1000_1000;

/// Ending address for VirtIO device probe.
const VIRTIO_END: usize = 0x1000_8000;

/// VirtIO magic number identifier.
const VIRTIO_MAGIC: u32 = 0x74726976;

/// Device ID for network devices.
const DEVICE_ID_NET: u32 = 1;

/// VirtIO specification version 1.0.
const DEVICE_VERSION_1: u32 = 1;

/// Status register offset.
const STATUS: usize = 0x070;

/// Queue selection register offset.
const QUEUE_SEL: usize = 0x030;

/// Queue size register offset.
const QUEUE_NUM: usize = 0x038;

/// Queue alignment register offset.
const QUEUE_ALIGN: usize = 0x03c;

/// Queue physical frame number register offset.
const QUEUE_PFN: usize = 0x040;

/// Queue notify register offset.
const QUEUE_NOTIFY: usize = 0x050;

/// Number of descriptors in each queue.
const QUEUE_SIZE: usize = 2;

/// Size of VirtIO network header in bytes.
const NET_HDR_SIZE: usize = 10;

/// Maximum buffer size for packet storage.
const BUF_SIZE: usize = 1536;

/// VirtIO queue descriptor structure.
///
/// Describes a single buffer in the virtqueue. The descriptor contains
/// the physical address of the buffer, its length, and flags indicating
/// whether it's writable and whether it chains to another descriptor.
#[repr(C, align(16))]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

/// VirtIO available ring structure.
///
/// The available ring is used by the driver to notify the device
/// about buffers that are ready for processing.
#[repr(C, align(2))]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE],
    event: u16,
}

/// Element in the used ring.
///
/// Contains the descriptor ID and length of data written by the device.
#[repr(C, align(4))]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

/// VirtIO used ring structure.
///
/// The used ring is used by the device to notify the driver about
/// buffers that have been processed and are ready to be recycled.
#[repr(C, align(4))]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; QUEUE_SIZE],
    event: u16,
}

/// Complete virtqueue structure.
///
/// Contains the descriptor table, available ring, packet buffers,
/// and used ring all in a single aligned structure for efficient
/// memory layout.
#[repr(C, align(4096))]
struct Queue {
    desc: [VirtqDesc; QUEUE_SIZE],
    avail: VirtqAvail,
    _pad_align: [u8; 6],
    buffers: [[u8; BUF_SIZE]; QUEUE_SIZE],
    _pad_rest: [u8; 4096 - 48 - (BUF_SIZE * QUEUE_SIZE)],
    used: VirtqUsed,
}

/// Receive queue for incoming packets.
static mut RX_QUEUE: Queue = unsafe { core::mem::zeroed() };

/// Transmit queue for outgoing packets.
static mut TX_QUEUE: Queue = unsafe { core::mem::zeroed() };

/// Current index in the receive used ring.
static mut RX_IDX: u16 = 0;

/// Base address of the active VirtIO device.
static mut ACTIVE_BASE: usize = 0;

/// Last received descriptor ID for buffer recycling.
static mut LAST_RX_ID: u16 = 0;

/// VirtIO network device driver.
///
/// Provides methods for initializing the device, receiving packets,
/// and sending packets through the VirtIO interface.
pub struct VirtioNet;

impl VirtioNet {
    /// Initializes the VirtIO network device.
    ///
    /// Probes for a VirtIO network device, configures the queues,
    /// and sets up the device for operation. This must be called
    /// once before using the device.
    pub fn init() {
        kprint!("[VirtIO] Probing... ");
        let mut addr = VIRTIO_START;
        while addr <= VIRTIO_END {
            unsafe {
                if read_volatile((addr) as *const u32) == VIRTIO_MAGIC {
                    if read_volatile((addr + 8) as *const u32) == DEVICE_ID_NET {
                        if read_volatile((addr + 4) as *const u32) == DEVICE_VERSION_1 {
                            ACTIVE_BASE = addr;
                            break;
                        }
                    }
                }
            }
            addr += 0x1000;
        }

        if unsafe { ACTIVE_BASE } == 0 {
            panic!("No Legacy Net Device Found");
        }
        kprintln!("Found at {:#x}", unsafe { ACTIVE_BASE });

        Self::reg_write(STATUS, 0);
        Self::reg_write(STATUS, 0x01 | 0x02);
        Self::reg_write(0x020, 0);
        Self::reg_write(STATUS, 0x01 | 0x02 | 0x08);

        unsafe {
            let rx = addr_of_mut!(RX_QUEUE);
            for i in 0..QUEUE_SIZE {
                (*rx).desc[i].addr = addr_of_mut!((*rx).buffers[i]) as u64;
                (*rx).desc[i].len = BUF_SIZE as u32;
                (*rx).desc[i].flags = 2;
                (*rx).avail.ring[i] = i as u16;
            }
            (*rx).avail.idx = QUEUE_SIZE as u16;
        }

        Self::reg_write(0x028, 4096);

        Self::reg_write(QUEUE_SEL, 0);
        Self::reg_write(QUEUE_NUM, QUEUE_SIZE as u32);
        Self::reg_write(QUEUE_ALIGN, 4096);
        Self::reg_write(QUEUE_PFN, (addr_of_mut!(RX_QUEUE) as u32) >> 12);

        Self::reg_write(QUEUE_SEL, 1);
        Self::reg_write(QUEUE_NUM, QUEUE_SIZE as u32);
        Self::reg_write(QUEUE_ALIGN, 4096);
        Self::reg_write(QUEUE_PFN, (addr_of_mut!(TX_QUEUE) as u32) >> 12);

        Self::reg_write(STATUS, 0x01 | 0x02 | 0x08 | 0x04);
        kprintln!("[VirtIO] Driver OK");
    }

    /// Writes a 32-bit value to a VirtIO register.
    ///
    /// # Arguments
    ///
    /// * `offset` - Register offset from device base address
    /// * `val` - Value to write
    fn reg_write(offset: usize, val: u32) {
        unsafe { write_volatile((ACTIVE_BASE + offset) as *mut u32, val) }
    }

    /// Attempts to receive a packet from the network device.
    ///
    /// Checks the used ring for new packets and returns a mutable
    /// slice to the packet data if available. The caller must call
    /// `recycle_rx_buffer()` after processing the packet.
    ///
    /// # Returns
    ///
    /// Some mutable slice to packet data if a packet is available,
    /// None otherwise.
    pub fn try_receive() -> Option<&'static mut [u8]> {
        unsafe {
            let rx = addr_of_mut!(RX_QUEUE);
            let used_idx = read_volatile(addr_of_mut!((*rx).used.idx));
            if used_idx != RX_IDX {
                fence(Ordering::SeqCst);
                let ring_idx = RX_IDX as usize % QUEUE_SIZE;
                let id = (*rx).used.ring[ring_idx].id as usize;
                let len = (*rx).used.ring[ring_idx].len as usize;

                if id >= QUEUE_SIZE {
                    RX_IDX = RX_IDX.wrapping_add(1);
                    return None;
                }

                RX_IDX = RX_IDX.wrapping_add(1);
                LAST_RX_ID = id as u16;

                if len > NET_HDR_SIZE {
                    let buf_ptr = addr_of_mut!((*rx).buffers[id]) as *mut u8;
                    let data_ptr = buf_ptr.add(NET_HDR_SIZE);
                    let data_len = len - NET_HDR_SIZE;
                    return Some(core::slice::from_raw_parts_mut(data_ptr, data_len));
                }
            }
        }
        None
    }

    /// Recycles a receive buffer back to the available ring.
    ///
    /// This must be called after processing a packet received from
    /// `try_receive()` to return the buffer to the device for reuse.
    pub fn recycle_rx_buffer() {
        unsafe {
            let rx = addr_of_mut!(RX_QUEUE);
            let idx = (*rx).avail.idx;
            (*rx).avail.ring[idx as usize % QUEUE_SIZE] = LAST_RX_ID;
            fence(Ordering::SeqCst);
            (*rx).avail.idx = idx.wrapping_add(1);
        }
    }

    /// Sends a packet through the network device.
    ///
    /// Copies the packet data into a transmit buffer and notifies
    /// the device. The packet should be a complete Ethernet frame.
    ///
    /// # Arguments
    ///
    /// * `packet` - Complete Ethernet frame to transmit
    pub fn send(packet: &[u8]) {
        unsafe {
            let tx = addr_of_mut!(TX_QUEUE);
            let idx = (*tx).avail.idx as usize % QUEUE_SIZE;

            let buf_ptr = addr_of_mut!((*tx).buffers[idx]) as *mut u8;

            core::ptr::write_bytes(buf_ptr, 0, NET_HDR_SIZE);

            core::ptr::copy_nonoverlapping(
                packet.as_ptr(),
                buf_ptr.add(NET_HDR_SIZE),
                packet.len(),
            );

            (*tx).desc[idx].addr = buf_ptr as u64;
            (*tx).desc[idx].len = (NET_HDR_SIZE + packet.len()) as u32;
            (*tx).desc[idx].flags = 0;
            (*tx).avail.ring[idx] = idx as u16;

            fence(Ordering::SeqCst);
            (*tx).avail.idx = (*tx).avail.idx.wrapping_add(1);
        }
    }

    /// Flushes the transmit queue by notifying the device.
    ///
    /// This triggers the device to process any pending transmit
    /// descriptors. Should be called after sending packets or
    /// periodically to ensure timely transmission.
    pub fn flush() {
        unsafe {
            write_volatile((ACTIVE_BASE + QUEUE_NOTIFY) as *mut u32, 0);
            write_volatile((ACTIVE_BASE + QUEUE_NOTIFY) as *mut u32, 1);
        }
    }
}
