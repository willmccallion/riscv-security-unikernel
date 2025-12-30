use core::ptr::null_mut;

pub const SLAB_SIZE: usize = 256;
pub const NUM_SLABS: usize = 4;

#[derive(Copy, Clone)]
#[repr(align(4))]
pub struct Slab {
    #[allow(dead_code)]
    pub data: [u8; SLAB_SIZE],
    #[allow(dead_code)]
    pub len: usize,
    pub next: *mut Slab,
}

pub struct SlabAllocator {
    pub pool: [Slab; NUM_SLABS],
    pub free_head: *mut Slab,
}

impl SlabAllocator {
    pub const fn new() -> Self {
        Self {
            pool: [Slab {
                data: [0; SLAB_SIZE],
                len: 0,
                next: null_mut(),
            }; NUM_SLABS],
            free_head: null_mut(),
        }
    }

    pub fn init(&mut self) {
        for i in 0..NUM_SLABS - 1 {
            self.pool[i].next = &mut self.pool[i + 1];
        }
        self.pool[NUM_SLABS - 1].next = null_mut();
        self.free_head = &mut self.pool[0];
    }
}

pub static mut ALLOCATOR: SlabAllocator = SlabAllocator::new();
