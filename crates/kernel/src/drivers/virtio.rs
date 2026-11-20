//! VirtIO network device driver.
//!
//! Implements the VirtIO 1.0 legacy interface for network device access.
//! This driver manages receive and transmit queues, handles packet
//! buffers, and provides a simple interface for sending and receiving
//! Ethernet frames.

use super::virtio_mmio::{DESC_F_WRITE, DeviceId, Mmio, Queue};
use crate::{kprint, kprintln};
use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

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

/// Receive queue for incoming packets.
// SAFETY: Queue consists entirely of integer types; zeroing all bytes produces a valid initial state.
static mut RX_RING: Queue<QUEUE_SIZE> = unsafe { core::mem::zeroed() };

/// Transmit queue for outgoing packets.
// SAFETY: Queue consists entirely of integer types; zeroing all bytes produces a valid initial state.
static mut TX_RING: Queue<QUEUE_SIZE> = unsafe { core::mem::zeroed() };

/// Packet buffers the RX descriptors point at.
static mut RX_BUFFERS: [[u8; BUF_SIZE]; QUEUE_SIZE] = [[0; BUF_SIZE]; QUEUE_SIZE];

/// Packet buffers the TX descriptors point at.
static mut TX_BUFFERS: [[u8; BUF_SIZE]; QUEUE_SIZE] = [[0; BUF_SIZE]; QUEUE_SIZE];

/// Current index in the receive used ring.
static mut RX_IDX: u16 = 0;

/// The device's registers, once probed.
static mut DEVICE: Option<Mmio> = None;

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
        let Some(mmio) = Mmio::probe(DeviceId::Net) else {
            panic!("No Legacy Net Device Found");
        };
        // SAFETY: DEVICE is only written here, during single-threaded init.
        unsafe { DEVICE = Some(mmio) };
        kprintln!("Found at {:#x}", mmio.base());
        mmio.begin_setup();

        // SAFETY: RX_RING and RX_BUFFERS are statics only accessed from this
        // single-threaded kernel, so the descriptors' buffer addresses stay
        // valid; the device reads these fields, so they are written volatile.
        unsafe {
            let rx = addr_of_mut!(RX_RING);
            let buffers = addr_of_mut!(RX_BUFFERS).cast::<[u8; BUF_SIZE]>();
            for id in 0..QUEUE_SIZE {
                let desc = addr_of_mut!((*rx).desc[id]);
                write_volatile(addr_of_mut!((*desc).addr), buffers.add(id) as u64);
                write_volatile(addr_of_mut!((*desc).len), BUF_SIZE as u32);
                write_volatile(addr_of_mut!((*desc).flags), DESC_F_WRITE);
                write_volatile(addr_of_mut!((*rx).avail.ring[id]), id as u16);
            }
            write_volatile(addr_of_mut!((*rx).avail.idx), QUEUE_SIZE as u16);
        }

        mmio.install_queue(RX_QUEUE, addr_of!(RX_RING));
        mmio.install_queue(TX_QUEUE, addr_of!(TX_RING));
        mmio.finish_setup();
        kprintln!("[VirtIO] Driver OK");
    }

    /// Lends the next received frame to `handle`, then gives its buffer
    /// back to the device.
    ///
    /// Returns `None` if no frame is waiting or the device returned one with
    /// no usable frame, which is dropped. The frame cannot outlive `handle`,
    /// so its buffer is never in use while the device owns it again.
    pub fn receive<R>(handle: impl FnOnce(&mut [u8]) -> R) -> Option<R> {
        let (id, len) = Self::next_used_rx()?;
        // An id we never posted has no buffer to hand back.
        if id >= QUEUE_SIZE {
            return None;
        }
        // A runt (header only) or a length past the end of our buffer
        // carries no usable frame.
        let result = (NET_HDR_SIZE < len && len <= BUF_SIZE).then(|| {
            // SAFETY: the device has returned buffer `id`, and it is not
            // reposted until `recycle_rx_buffer` below, so nothing else
            // touches these `len - NET_HDR_SIZE` bytes while `handle` runs.
            let frame = unsafe {
                let buf = addr_of_mut!(RX_BUFFERS[id]).cast::<u8>();
                core::slice::from_raw_parts_mut(buf.add(NET_HDR_SIZE), len - NET_HDR_SIZE)
            };
            handle(frame)
        });
        Self::recycle_rx_buffer(id);
        result
    }

    /// The descriptor id and length of the next buffer the device returned,
    /// consuming that used-ring entry.
    fn next_used_rx() -> Option<(usize, usize)> {
        // SAFETY: RX_RING and RX_IDX are statics only accessed from this
        // single-threaded polling loop; the device writes the used ring, so
        // it is read volatile, and the ring index is masked to QUEUE_SIZE.
        unsafe {
            let rx = addr_of!(RX_RING);
            if read_volatile(addr_of!((*rx).used.idx)) == RX_IDX {
                return None;
            }
            fence(Ordering::SeqCst);
            let elem = addr_of!((*rx).used.ring[RX_IDX as usize % QUEUE_SIZE]);
            let id = read_volatile(addr_of!((*elem).id)) as usize;
            let len = read_volatile(addr_of!((*elem).len)) as usize;
            RX_IDX = RX_IDX.wrapping_add(1);
            Some((id, len))
        }
    }

    /// Posts receive buffer `id` back to the device.
    fn recycle_rx_buffer(id: usize) {
        // SAFETY: RX_RING is a mutable static only accessed from this
        // single-threaded kernel; the device reads the available ring, so it
        // is written volatile, and the ring index is masked to QUEUE_SIZE.
        unsafe {
            let rx = addr_of_mut!(RX_RING);
            let idx = read_volatile(addr_of!((*rx).avail.idx));
            write_volatile(
                addr_of_mut!((*rx).avail.ring[idx as usize % QUEUE_SIZE]),
                id as u16,
            );
            fence(Ordering::SeqCst);
            write_volatile(addr_of_mut!((*rx).avail.idx), idx.wrapping_add(1));
        }
    }

    /// Sends a packet through the network device.
    ///
    /// Copies the packet data into a transmit buffer and notifies
    /// the device. The packet should be a complete Ethernet frame.
    pub fn send(packet: &[u8]) {
        // The packet body has to fit alongside the 10-byte VirtIO net
        // header in a single `BUF_SIZE` buffer. Current callers all
        // pass small stack buffers, but silently corrupting adjacent
        // queue memory on the first oversize caller would be an ugly
        // bug to hunt.
        if packet.len() > BUF_SIZE - NET_HDR_SIZE {
            return;
        }
        if !Self::wait_for_free_tx_slot() {
            return;
        }
        // SAFETY: TX_RING is a mutable static only accessed from this single-threaded kernel.
        // Volatile writes and a fence ensure the device sees the descriptor before the available
        // index is updated.
        unsafe {
            let tx = addr_of_mut!(TX_RING);
            let avail_idx = read_volatile(addr_of!((*tx).avail.idx));
            let idx = avail_idx as usize % QUEUE_SIZE;

            let buf_ptr = addr_of_mut!(TX_BUFFERS[idx]).cast::<u8>();

            core::ptr::write_bytes(buf_ptr, 0, NET_HDR_SIZE);

            core::ptr::copy_nonoverlapping(
                packet.as_ptr(),
                buf_ptr.add(NET_HDR_SIZE),
                packet.len(),
            );

            let desc = addr_of_mut!((*tx).desc[idx]);
            write_volatile(addr_of_mut!((*desc).addr), buf_ptr as u64);
            write_volatile(
                addr_of_mut!((*desc).len),
                (NET_HDR_SIZE + packet.len()) as u32,
            );
            write_volatile(addr_of_mut!((*desc).flags), 0);
            write_volatile(addr_of_mut!((*tx).avail.ring[idx]), idx as u16);

            fence(Ordering::SeqCst);
            write_volatile(addr_of_mut!((*tx).avail.idx), avail_idx.wrapping_add(1));
        }
    }

    /// Returns once the device has released a TX descriptor, kicking it
    /// first if the ring is full. Returns `false` if it never does, in
    /// which case the caller drops the frame rather than overwrite a
    /// buffer the device still owns.
    fn wait_for_free_tx_slot() -> bool {
        if Self::tx_in_flight() < QUEUE_SIZE {
            return true;
        }
        Self::flush();
        for _ in 0..TX_RECLAIM_SPINS {
            if Self::tx_in_flight() < QUEUE_SIZE {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Number of TX descriptors handed to the device and not yet returned.
    fn tx_in_flight() -> usize {
        // SAFETY: TX_RING is a mutable static only accessed from this
        // single-threaded kernel; the device updates `used.idx`, so it is
        // read volatile.
        unsafe {
            let tx = addr_of_mut!(TX_RING);
            let used = read_volatile(addr_of!((*tx).used.idx));
            read_volatile(addr_of!((*tx).avail.idx)).wrapping_sub(used) as usize
        }
    }

    /// Flushes the transmit queue by notifying the device.
    ///
    /// This triggers the device to process any pending transmit
    /// descriptors. Should be called after sending packets or
    /// periodically to ensure timely transmission.
    pub fn flush() {
        // SAFETY: DEVICE is only written during single-threaded init.
        if let Some(mmio) = unsafe { DEVICE } {
            mmio.notify(RX_QUEUE);
            mmio.notify(TX_QUEUE);
        }
    }
}
