//! When the engine's periodic work falls due.

use crate::config::{CMS_DECAY_INTERVAL, TELEMETRY_INTERVAL};
use crate::time::{TickSpan, Ticks};

/// Tracks the telemetry and detection intervals so every caller ends them
/// on the same rule: an interval ends once its full length has passed
/// since the previous end, and the next one starts then.
#[derive(Debug, Clone, Copy)]
pub struct Schedule {
    telemetry: Period,
    detection: Period,
}

/// The intervals that ended at one check, with how long each actually
/// ran: past its nominal length when the check came late.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Due {
    /// Prune flows, report the interval's counters and start a new one.
    pub telemetry: Option<TickSpan>,
    /// Call [`Engine::end_detection_interval`](super::Engine::end_detection_interval).
    pub detection: Option<TickSpan>,
}

impl Schedule {
    /// Intervals of [`TELEMETRY_INTERVAL`] and [`CMS_DECAY_INTERVAL`], both
    /// starting at `now`.
    pub const fn new(now: Ticks) -> Self {
        Self {
            telemetry: Period::new(TELEMETRY_INTERVAL, now),
            detection: Period::new(CMS_DECAY_INTERVAL, now),
        }
    }

    /// Which intervals have ended by `now`, starting the next of each.
    pub fn due(&mut self, now: Ticks) -> Due {
        Due {
            telemetry: self.telemetry.end_if_over(now),
            detection: self.detection.end_if_over(now),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Period {
    length: TickSpan,
    start: Ticks,
}

impl Period {
    const fn new(length: TickSpan, start: Ticks) -> Self {
        Self { length, start }
    }

    /// How long the period ran, if it has reached its length by `now`;
    /// the next starts at `now`.
    fn end_if_over(&mut self, now: Ticks) -> Option<TickSpan> {
        let elapsed = now.since(self.start);
        if elapsed < self.length {
            return None;
        }
        self.start = now;
        Some(elapsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const START: Ticks = Ticks::new(1_000);

    fn at(offset: TickSpan) -> Ticks {
        START + offset
    }

    #[test]
    fn nothing_is_due_before_an_interval_has_passed() {
        let mut schedule = Schedule::new(START);

        let early = TickSpan::new(CMS_DECAY_INTERVAL.get() - 1);

        assert_eq!(schedule.due(at(early)), Due::default());
    }

    #[test]
    fn an_interval_ends_exactly_when_its_length_has_passed() {
        let mut schedule = Schedule::new(START);

        let due = schedule.due(at(CMS_DECAY_INTERVAL));

        assert_eq!(due.detection, Some(CMS_DECAY_INTERVAL));
        assert_eq!(due.telemetry, None);
    }

    #[test]
    fn a_late_check_reports_how_long_the_interval_ran() {
        let mut schedule = Schedule::new(START);
        let late = CMS_DECAY_INTERVAL * 3;

        assert_eq!(schedule.due(at(late)).detection, Some(late));
    }

    #[test]
    fn both_end_together_when_both_have_passed() {
        let mut schedule = Schedule::new(START);

        let due = schedule.due(at(TELEMETRY_INTERVAL));

        assert_eq!(due.telemetry, Some(TELEMETRY_INTERVAL));
        assert_eq!(due.detection, Some(TELEMETRY_INTERVAL));
    }

    #[test]
    fn the_next_interval_starts_when_the_last_one_ended() {
        let mut schedule = Schedule::new(START);
        let checked_late = at(CMS_DECAY_INTERVAL * 2) + TickSpan::new(7);
        let _ = schedule.due(checked_late);

        let one_short = checked_late + TickSpan::new(CMS_DECAY_INTERVAL.get() - 1);

        assert_eq!(schedule.due(one_short).detection, None);
        assert_eq!(
            schedule.due(checked_late + CMS_DECAY_INTERVAL).detection,
            Some(CMS_DECAY_INTERVAL)
        );
    }

    #[test]
    fn intervals_end_across_a_wrap_of_the_clock() {
        let start = Ticks::new(u64::MAX - 10);
        let mut schedule = Schedule::new(start);

        let due = schedule.due(start.wrapping_add(TELEMETRY_INTERVAL));

        assert_eq!(due.telemetry, Some(TELEMETRY_INTERVAL));
    }
}
