//! Time-source abstraction.
//!
//! Lets `sec-core` logic run on both RISC-V (`mcycle` CSR) and Linux
//! (`CLOCK_MONOTONIC`) without `#[cfg]` contamination in the security
//! modules themselves.
//!
//! The unit of [`TimeSource::now`] is implementation-defined (cycles on
//! RISC-V, nanoseconds on Linux): readings are [`Ticks`] and durations
//! [`TickSpan`]s in that unit.

use core::ops::{Add, AddAssign, Div, Mul};

/// Monotonically non-decreasing counter.
pub trait TimeSource {
    /// Returns the current time-source value.
    ///
    /// Successive calls must never decrease. The concrete unit is
    /// defined by the implementation.
    fn now(&self) -> Ticks;
}

/// A reading of the time source, in its implementation's unit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Ticks(u64);

/// A length of time in the time source's unit.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct TickSpan(u64);

impl Ticks {
    /// The first reading: the counter at boot.
    pub const ZERO: Self = Self(0);

    /// The reading `count`.
    pub const fn new(count: u64) -> Self {
        Self(count)
    }

    /// The raw counter value.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The time from `earlier` to this reading, correct across one wrap of
    /// the counter.
    pub const fn since(self, earlier: Self) -> TickSpan {
        TickSpan(self.0.wrapping_sub(earlier.0))
    }

    /// `span` after this reading, or the last reading there is.
    #[must_use]
    pub const fn saturating_add(self, span: TickSpan) -> Self {
        Self(self.0.saturating_add(span.0))
    }

    /// `span` after this reading, wrapping as the counter does.
    #[must_use]
    pub const fn wrapping_add(self, span: TickSpan) -> Self {
        Self(self.0.wrapping_add(span.0))
    }
}

impl Add<TickSpan> for Ticks {
    type Output = Self;

    fn add(self, span: TickSpan) -> Self {
        Self(self.0 + span.0)
    }
}

impl AddAssign<TickSpan> for Ticks {
    fn add_assign(&mut self, span: TickSpan) {
        self.0 += span.0;
    }
}

impl TickSpan {
    /// No time at all.
    pub const ZERO: Self = Self(0);

    /// A span of `count` units.
    pub const fn new(count: u64) -> Self {
        Self(count)
    }

    /// The span in the time source's unit.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// How many whole `per` spans fit in this one.
impl Div for TickSpan {
    type Output = u64;

    fn div(self, per: Self) -> u64 {
        self.0 / per.0
    }
}

impl Mul<u64> for TickSpan {
    type Output = Self;

    fn mul(self, count: u64) -> Self {
        Self(self.0 * count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_time_since_an_earlier_reading_survives_the_counter_wrapping() {
        let before_wrap = Ticks::new(u64::MAX - 4);
        let after_wrap = Ticks::new(5);

        assert_eq!(after_wrap.since(before_wrap), TickSpan::new(10));
    }

    #[test]
    fn a_span_past_the_last_reading_saturates() {
        let near_the_end = Ticks::new(u64::MAX - 1);

        assert_eq!(
            near_the_end.saturating_add(TickSpan::new(10)),
            Ticks::new(u64::MAX)
        );
    }

    #[test]
    fn whole_spans_divide_and_multiply_back() {
        let span = TickSpan::new(35);
        let per = TickSpan::new(10);

        assert_eq!(span / per, 3);
        assert_eq!(per * 3, TickSpan::new(30));
    }
}
