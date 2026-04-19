//! Time-source abstraction.
//!
//! Lets `sec-core` logic run on both RISC-V (`mcycle` CSR) and Linux
//! (`CLOCK_MONOTONIC`) without `#[cfg]` contamination in the security
//! modules themselves.
//!
//! The unit of [`TimeSource::now`] is implementation-defined (cycles on
//! RISC-V, nanoseconds on Linux) — callers must use threshold constants
//! with matching units.

/// Monotonically non-decreasing counter.
pub trait TimeSource {
    /// Returns the current time-source value.
    ///
    /// Successive calls must never decrease. The concrete unit is
    /// defined by the implementation.
    fn now(&self) -> u64;
}
