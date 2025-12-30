use crate::{kprint, kprintln};
use core::ptr::{addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

const VIRTIO_START: usize = 0x1000_1000;
const VIRTIO_END: usize = 0x1000_8000;
const VIRTIO_MAGIC: u32 = 0x74726976;
const DEVICE_ID_NET: u32 = 1;
const DEVICE_VERSION_1: u32 = 1;

const STATUS: usize = 0x070;
const QUEUE_SEL: usize = 0x030;
const QUEUE_NUM: usize = 0x038;
const QUEUE_ALIGN: usize = 0x03c;
const QUEUE_PFN: usize = 0x040;
const QUEUE_NOTIFY: usize = 0x050;

const QUEUE_SIZE: usize = 2;
const NET_HDR_SIZE: usize = 10;
const BUF_SIZE: usize = 1536;

#[repr(C, align(16))]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C, align(2))]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE],
    event: u16,
}

#[repr(C, align(4))]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

#[repr(C, align(4))]
struct VirtqUsed {
    flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; QUEUE_SIZE],
    event: u16,
}

#[repr(C, align(4096))]
struct Queue {
    desc: [VirtqDesc; QUEUE_SIZE],
    avail: VirtqAvail,
    _pad_align: [u8; 6],
    buffers: [[u8; BUF_SIZE]; QUEUE_SIZE],
    _pad_rest: [u8; 4096 - 48 - (BUF_SIZE * QUEUE_SIZE)],
    used: VirtqUsed,
}

static mut RX_QUEUE: Queue = unsafe { core::mem::zeroed() };
static mut TX_QUEUE: Queue = unsafe { core::mem::zeroed() };

static mut RX_IDX: u16 = 0;
static mut ACTIVE_BASE: usize = 0;
static mut LAST_RX_ID: u16 = 0;

pub struct VirtioNet;

impl VirtioNet {
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

        Self::reg_write(STATUS, 0); // Reset
        Self::reg_write(STATUS, 0x01 | 0x02); // Acknowledge | Driver
        Self::reg_write(0x020, 0); // Features
        Self::reg_write(STATUS, 0x01 | 0x02 | 0x08); // Features OK

        unsafe {
            let rx = addr_of_mut!(RX_QUEUE);
            for i in 0..QUEUE_SIZE {
                // Point descriptor to the embedded buffer
                (*rx).desc[i].addr = addr_of_mut!((*rx).buffers[i]) as u64;
                (*rx).desc[i].len = BUF_SIZE as u32;
                (*rx).desc[i].flags = 2; // Write-only
                (*rx).avail.ring[i] = i as u16;
            }
            (*rx).avail.idx = QUEUE_SIZE as u16;
        }

        Self::reg_write(0x028, 4096); // Page size

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

    fn reg_write(offset: usize, val: u32) {
        unsafe { write_volatile((ACTIVE_BASE + offset) as *mut u32, val) }
    }

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

    pub fn recycle_rx_buffer() {
        unsafe {
            let rx = addr_of_mut!(RX_QUEUE);
            let idx = (*rx).avail.idx;
            (*rx).avail.ring[idx as usize % QUEUE_SIZE] = LAST_RX_ID;
            fence(Ordering::SeqCst);
            (*rx).avail.idx = idx.wrapping_add(1);
        }
    }

    pub fn send(packet: &[u8]) {
        unsafe {
            let tx = addr_of_mut!(TX_QUEUE);
            let idx = (*tx).avail.idx as usize % QUEUE_SIZE;

            let buf_ptr = addr_of_mut!((*tx).buffers[idx]) as *mut u8;

            // Zero header (memset)
            core::ptr::write_bytes(buf_ptr, 0, NET_HDR_SIZE);

            // Copy packet (memcpy)
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

    pub fn flush() {
        unsafe {
            write_volatile((ACTIVE_BASE + QUEUE_NOTIFY) as *mut u32, 0);
            write_volatile((ACTIVE_BASE + QUEUE_NOTIFY) as *mut u32, 1);
        }
    }
}
