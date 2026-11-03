//! Type definitions for kernel global state management.
//!
//! Provides [`TakeOnce`], which lets a `static` hold state that one
//! execution context borrows mutably for the life of the program.

#![allow(unsafe_code)]

use core::cell::UnsafeCell;
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};

/// A `static` value that can be borrowed mutably exactly once.
///
/// The kernel keeps its engine in one of these because the engine is too
/// big for the stack. [`TakeOnce::take`] hands out the only `&mut T` and
/// returns `None` ever after, so two mutable references can never exist,
/// whatever the caller does.
pub struct TakeOnce<T> {
    data: UnsafeCell<T>,
    taken: AtomicBool,
}

// SAFETY: `take` gives out at most one `&mut T`, so sharing a `TakeOnce`
// only shares the right to move `T` into one context, which `T: Send` allows.
unsafe impl<T: Send> Sync for TakeOnce<T> {}

impl<T> fmt::Debug for TakeOnce<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TakeOnce")
            .field("taken", &self.taken.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl<T> TakeOnce<T> {
    /// Creates a `TakeOnce` holding `data`, not yet taken.
    pub const fn new(data: T) -> Self {
        Self {
            data: UnsafeCell::new(data),
            taken: AtomicBool::new(false),
        }
    }

    /// The value, mutably, on the first call; `None` on every later one.
    #[allow(clippy::mut_from_ref)]
    pub fn take(&self) -> Option<&mut T> {
        if self.taken.swap(true, Ordering::Acquire) {
            return None;
        }
        // SAFETY: `taken` was false, so no `&mut T` to `data` exists, and
        // setting it means no later call will create another.
        Some(unsafe { &mut *self.data.get() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Also run under `cargo +nightly miri test -p sec-core`, which flags any
    // aliasing UB in the `UnsafeCell` access.
    #[test]
    fn take_once_keeps_writes_made_through_its_value() {
        static CELL: TakeOnce<u32> = TakeOnce::new(0);
        let value = CELL.take().expect("first take");

        *value = 0xDEAD_BEEF;

        assert_eq!(*value, 0xDEAD_BEEF);
    }

    #[test]
    fn take_once_hands_out_its_value_only_once() {
        let cell = TakeOnce::new(7u32);
        let first = cell.take();

        let second = cell.take();

        assert_eq!(first.copied(), Some(7));
        assert!(second.is_none());
    }
}
