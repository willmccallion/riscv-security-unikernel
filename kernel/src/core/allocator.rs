//! Slab allocator for fixed-size memory allocations.
//!
//! This module provides a simple slab allocator optimized for small,
//! fixed-size allocations. It maintains a pool of pre-allocated slabs
//! linked in a free list for O(1) allocation and deallocation.

use core::ptr::null_mut;

/// Size of each slab in bytes.
pub const SLAB_SIZE: usize = 256;

/// Number of slabs in the allocator pool.
pub const NUM_SLABS: usize = 4;

/// A single memory slab in the allocator pool.
///
/// Slabs are linked together in a free list using the `next` pointer.
/// When allocated, the `data` array is used to store the actual data.
#[derive(Copy, Clone)]
#[repr(align(4))]
pub struct Slab {
    /// Raw data storage for this slab.
    #[allow(dead_code)]
    pub data: [u8; SLAB_SIZE],
    /// Length of data currently stored in this slab.
    #[allow(dead_code)]
    pub len: usize,
    /// Pointer to the next slab in the free list.
    pub next: *mut Slab,
}

/// Slab allocator managing a fixed pool of memory slabs.
///
/// Maintains a free list of available slabs and provides
/// constant-time allocation and deallocation operations.
pub struct SlabAllocator {
    /// Array of all slabs in the pool.
    pub pool: [Slab; NUM_SLABS],
    /// Head of the free list, null if no slabs available.
    pub free_head: *mut Slab,
}

impl SlabAllocator {
    /// Creates a new slab allocator with uninitialized free list.
    ///
    /// The allocator must be initialized with `init()` before use.
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

    /// Initializes the free list by linking all slabs together.
    ///
    /// This must be called once before the allocator is used.
    pub fn init(&mut self) {
        for i in 0..NUM_SLABS - 1 {
            self.pool[i].next = &mut self.pool[i + 1];
        }
        self.pool[NUM_SLABS - 1].next = null_mut();
        self.free_head = &mut self.pool[0];
    }
}

/// Global slab allocator instance.
///
/// # Safety
///
/// This is safe in a single-threaded kernel environment. Access
/// must be synchronized if used in a multi-threaded context.
pub static mut ALLOCATOR: SlabAllocator = SlabAllocator::new();
