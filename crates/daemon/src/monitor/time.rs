//! Wall-clock instants as the monitor measures them.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A moment, as nanoseconds since the Unix epoch. Captured packets carry
/// one from the kernel or the capture file, so replaying a file
/// reproduces the timing of the original capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixNanos(u64);

impl UnixNanos {
    /// The moment `nanos` nanoseconds after the epoch.
    pub const fn new(nanos: u64) -> Self {
        Self(nanos)
    }

    /// The current wall-clock time.
    pub fn now() -> Self {
        let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
        Self(u64::try_from(since_epoch.as_nanos()).unwrap_or(u64::MAX))
    }

    /// Nanoseconds since the epoch.
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// The start of the `period`-long slot containing this moment, with
    /// slots aligned to the epoch.
    pub const fn floor_to(self, period: Duration) -> Self {
        let period = period.as_nanos() as u64;
        if period == 0 { self } else { Self(self.0 - self.0 % period) }
    }

    /// This moment plus `duration`, saturating at the far future.
    pub const fn saturating_add(self, duration: Duration) -> Self {
        Self(self.0.saturating_add(duration.as_nanos() as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floors_to_epoch_aligned_slots() {
        let t = UnixNanos::new(12_345_678_901);

        assert_eq!(t.floor_to(Duration::from_secs(1)), UnixNanos::new(12_000_000_000));
        assert_eq!(t.floor_to(Duration::ZERO), t);
    }
}
