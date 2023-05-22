use core::ops::Add;
use std::time::{UNIX_EPOCH, SystemTime, Instant, Duration};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CanonicalInstant {
  /// Time since the epoch.
  time: u64,
  /// An Instant synchronized with the above time.
  instant: Instant,
}

pub(crate) fn sys_time(time: u64) -> SystemTime {
  UNIX_EPOCH + Duration::from_secs(time)
}

impl CanonicalInstant {
  pub fn new(time: u64) -> CanonicalInstant {
    // This is imprecise yet should be precise enough, as it'll resolve within a few ms
    let instant_now = Instant::now();
    let sys_now = SystemTime::now();

    // If the time is in the future, this will be off by that much time
    let elapsed = sys_now.duration_since(sys_time(time)).unwrap_or(Duration::ZERO);
    // Except for the fact this panics here
    let synced_instant = instant_now.checked_sub(elapsed).unwrap();

    CanonicalInstant { time, instant: synced_instant }
  }

  pub fn canonical(&self) -> u64 {
    self.time
  }

  pub fn instant(&self) -> Instant {
    self.instant
  }
}

impl Add<Duration> for CanonicalInstant {
  type Output = CanonicalInstant;
  fn add(self, duration: Duration) -> CanonicalInstant {
    CanonicalInstant { time: self.time + duration.as_secs(), instant: self.instant + duration }
  }
}
