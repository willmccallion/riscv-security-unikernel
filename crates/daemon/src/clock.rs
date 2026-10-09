//! `CLOCK_MONOTONIC` as a [`TimeSource`].
//!
//! Nanoseconds tick at 1 GHz, the rate the engine's cycle-based
//! thresholds are documented against.

use sec_core::time::TimeSource;
use std::time::Instant;

/// Nanoseconds since the clock was created.
#[derive(Debug, Clone, Copy)]
pub struct Monotonic {
    start: Instant,
}

impl Monotonic {
    /// Starts a clock at zero.
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
        }
    }
}

impl TimeSource for Monotonic {
    fn now(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }
}
