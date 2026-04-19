//! RISC-V time-source implementation.
//!
//! Provides a zero-sized [`MCycle`] type that reads the `mcycle` CSR to
//! satisfy [`sec_core::time::TimeSource`]. M-mode on RV64 guarantees the
//! CSR is always available and monotonically non-decreasing, so the
//! implementation is a single `csrr` with no side effects.

use sec_core::time::TimeSource;

/// Zero-sized time source reading the RISC-V `mcycle` CSR.
#[derive(Debug, Default, Clone, Copy)]
pub struct MCycle;

impl TimeSource for MCycle {
    #[inline(always)]
    fn now(&self) -> u64 {
        let cycles: u64;
        // SAFETY: `csrr mcycle` reads a hardware counter with no side effects.
        // The CSR is always available in M-mode on RV64.
        unsafe { core::arch::asm!("csrr {}, mcycle", out(reg) cycles) }
        cycles
    }
}
