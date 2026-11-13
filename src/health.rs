//! Input quality and continuous invalid-exchange intervals, measured monotonically.
use serde::Serialize;
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InputIssue {
    Timeout,
    WorkingCounter,
    AlStatus,
    WorkingCounterAndAlStatus,
    TransportError,
}

impl InputIssue {
    pub fn label(self) -> &'static str {
        match self {
            Self::Timeout => "no reply",
            Self::WorkingCounter => "Working Counter mismatch",
            Self::AlStatus => "AL status invalid or unavailable",
            Self::WorkingCounterAndAlStatus => "Working Counter and AL status invalid",
            Self::TransportError => "Ethernet transport error",
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct InputHealth {
    pub current_issue: Option<InputIssue>,
    pub consecutive_invalid: u64,
    pub longest_invalid_streak: u64,
    pub invalid_periods: u64,
    pub recoveries: u64,
    pub last_valid_cycle: Option<u64>,
    pub last_valid_elapsed_us: Option<u64>,
    pub last_valid_age_us: Option<u64>,
    pub ongoing_invalid_us: u64,
    pub longest_invalid_us: u64,
}

pub(crate) struct Tracker {
    start: Instant,
    invalid_since: Option<Instant>,
    pub last_valid: Option<Instant>,
}

impl Tracker {
    pub fn new(start: Instant) -> Self {
        Self {
            start,
            invalid_since: None,
            last_valid: None,
        }
    }

    pub fn valid(&mut self, health: &mut InputHealth, cycle: u64, received: Instant) {
        self.refresh(health, received);
        if self.invalid_since.take().is_some() {
            health.recoveries += 1;
        }
        self.last_valid = Some(received);
        health.current_issue = None;
        health.consecutive_invalid = 0;
        health.ongoing_invalid_us = 0;
        health.last_valid_cycle = Some(cycle);
        health.last_valid_elapsed_us = Some(micros(received, self.start));
        health.last_valid_age_us = Some(0);
    }

    pub fn invalid(
        &mut self,
        health: &mut InputHealth,
        issue: InputIssue,
        sent: Instant,
        now: Instant,
    ) {
        if self.invalid_since.is_none() {
            self.invalid_since = Some(sent);
            health.invalid_periods += 1;
        }
        health.current_issue = Some(issue);
        health.consecutive_invalid += 1;
        health.longest_invalid_streak = health
            .longest_invalid_streak
            .max(health.consecutive_invalid);
        self.refresh(health, now);
    }

    pub fn refresh(&self, health: &mut InputHealth, now: Instant) {
        health.last_valid_age_us = self.last_valid.map(|at| micros(now, at));
        health.ongoing_invalid_us = self.invalid_since.map_or(0, |at| micros(now, at));
        health.longest_invalid_us = health.longest_invalid_us.max(health.ongoing_invalid_us);
    }
}

fn micros(now: Instant, earlier: Instant) -> u64 {
    now.saturating_duration_since(earlier).as_micros() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn preserves_gaps_and_last_good_time_across_different_failures() {
        let start = Instant::now();
        let at = |us| start + Duration::from_micros(us);
        let mut tracker = Tracker::new(start);
        let mut health = InputHealth::default();
        tracker.valid(&mut health, 1, at(100));
        tracker.invalid(&mut health, InputIssue::Timeout, at(1000), at(3000));
        tracker.invalid(&mut health, InputIssue::WorkingCounter, at(4000), at(4100));
        assert_eq!(health.last_valid_cycle, Some(1));
        assert_eq!(health.last_valid_age_us, Some(4000));
        assert_eq!(health.ongoing_invalid_us, 3100);
        tracker.valid(&mut health, 9, at(9000));
        assert_eq!(health.recoveries, 1);
        assert_eq!(health.invalid_periods, 1);
        assert_eq!(health.longest_invalid_streak, 2);
        assert_eq!(health.longest_invalid_us, 8000);
        assert_eq!(health.consecutive_invalid, 0);
        assert_eq!(health.current_issue, None);
        tracker.invalid(
            &mut health,
            InputIssue::TransportError,
            at(10_000),
            at(10_050),
        );
        tracker.refresh(&mut health, at(20_000));
        assert_eq!(health.last_valid_age_us, Some(11_000));
        assert_eq!(health.ongoing_invalid_us, 10_000);
        assert_eq!(health.longest_invalid_us, 10_000);
        assert_eq!(health.invalid_periods, 2);
        assert_eq!(health.last_valid_elapsed_us, Some(9000));
    }
}
