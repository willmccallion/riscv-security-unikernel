use core::cell::UnsafeCell;

/// A Zero-Overhead wrapper for global state in a single-threaded kernel.
#[repr(transparent)]
pub struct Singleton<T> {
    data: UnsafeCell<T>,
}

// SAFETY: This kernel is single-threaded (polling only), so Sync is safe
// as long as we don't use interrupts that access the same data.
unsafe impl<T> Sync for Singleton<T> {}

impl<T> Singleton<T> {
    pub const fn new(data: T) -> Self {
        Self {
            data: UnsafeCell::new(data),
        }
    }

    /// Access the global data.
    /// In a multi-threaded kernel, this would need a lock.
    #[allow(clippy::mut_from_ref)]
    pub fn get(&self) -> &mut T {
        unsafe { &mut *self.data.get() }
    }
}
