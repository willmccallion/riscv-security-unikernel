//! Change detection over per-interval measurements.

/// Flags an interval whose measurement jumps far above its recent
/// baseline, such as the number of distinct sources during a spoofed
/// flood.
///
/// The baseline is an exponentially weighted moving average of past
/// intervals. Intervals inside a surge are left out of it, so a long
/// attack does not become the new normal, and a surge is reported once,
/// when it starts.
#[derive(Debug, Clone, Copy)]
pub struct SurgeDetector {
    baseline: f64,
    intervals_seen: u32,
    in_surge: bool,
    factor: f64,
    minimum: f64,
}

impl SurgeDetector {
    /// Intervals observed before any surge can be reported.
    const WARMUP_INTERVALS: u32 = 4;
    /// Weight of each new interval in the baseline.
    const SMOOTHING: f64 = 0.125;

    /// A detector that fires when a measurement exceeds both `factor`
    /// times the baseline and the absolute `minimum`.
    pub const fn new(factor: f64, minimum: f64) -> Self {
        Self {
            baseline: 0.0,
            intervals_seen: 0,
            in_surge: false,
            factor,
            minimum,
        }
    }

    /// Feeds one interval's measurement; returns it if a surge starts here.
    pub fn observe(&mut self, measurement: f64) -> Option<f64> {
        let surging = self.intervals_seen >= Self::WARMUP_INTERVALS
            && measurement > self.minimum
            && measurement > self.factor * self.baseline;
        let starts = surging && !self.in_surge;
        self.in_surge = surging;
        if !surging {
            self.baseline = if self.intervals_seen == 0 {
                measurement
            } else {
                self.baseline + Self::SMOOTHING * (measurement - self.baseline)
            };
            self.intervals_seen = self.intervals_seen.saturating_add(1);
        }
        starts.then_some(measurement)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn warmed_up(level: f64) -> SurgeDetector {
        let mut d = SurgeDetector::new(4.0, 1000.0);
        for _ in 0..8 {
            assert_eq!(d.observe(level), None);
        }
        d
    }

    #[test]
    fn steady_traffic_never_fires() {
        let mut d = warmed_up(500.0);

        assert!((0..100).all(|_| d.observe(520.0).is_none()));
    }

    #[test]
    fn a_jump_well_above_baseline_fires_once() {
        let mut d = warmed_up(500.0);

        let first = d.observe(6000.0);
        let during = d.observe(6500.0);

        assert_eq!(first, Some(6000.0));
        assert_eq!(during, None, "a continuing surge is not re-reported");
    }

    #[test]
    fn a_surge_does_not_raise_the_baseline() {
        let mut d = warmed_up(500.0);
        for _ in 0..50 {
            let _ = d.observe(6000.0);
        }
        let _ = d.observe(500.0);

        assert_eq!(d.observe(6000.0), Some(6000.0), "the next surge is still a surge");
    }

    #[test]
    fn jumps_below_the_absolute_minimum_are_ignored() {
        let mut d = warmed_up(10.0);

        assert_eq!(d.observe(900.0), None);
    }

    #[test]
    fn nothing_fires_during_warmup() {
        let mut d = SurgeDetector::new(4.0, 1000.0);
        let _ = d.observe(10.0);

        assert_eq!(d.observe(50_000.0), None);
    }
}
