//! Type definitions for kernel global state management.
//!
//! Provides a Singleton pattern implementation for safely accessing
//! global mutable state in a single-threaded kernel environment.

use core::cell::UnsafeCell;

/// Zero-overhead wrapper for global mutable state in a single-threaded kernel.
///
/// This type provides interior mutability for global variables without
/// requiring locks, making it safe for use in a single-threaded polling
/// kernel environment. It uses UnsafeCell internally and implements Sync
/// based on the assumption that the kernel is single-threaded.
///
/// # Safety
///
/// This is only safe in a single-threaded kernel. If interrupts or
/// multiple execution contexts access the same Singleton, proper
/// synchronization must be added.
#[repr(transparent)]
pub struct Singleton<T> {
    data: UnsafeCell<T>,
}

/// Safety: This kernel operates in a single-threaded polling loop without
/// interrupts that access shared state. The Sync implementation is safe
/// under this execution model. If interrupts or multiple execution contexts
/// are introduced, proper synchronization primitives must be added.
unsafe impl<T> Sync for Singleton<T> {}

impl<T> Singleton<T> {
    /// Creates a new Singleton with the given initial value.
    ///
    /// # Arguments
    ///
    /// * `data` - Initial value for the singleton
    pub const fn new(data: T) -> Self {
        Self {
            data: UnsafeCell::new(data),
        }
    }

    /// Returns a mutable reference to the contained data.
    ///
    /// # Safety
    ///
    /// This is safe in a single-threaded kernel. In a multi-threaded
    /// environment, this would require synchronization primitives.
    ///
    /// # Returns
    ///
    /// Mutable reference to the singleton data
    #[allow(clippy::mut_from_ref)]
    pub fn get(&self) -> &mut T {
        unsafe { &mut *self.data.get() }
    }
}
