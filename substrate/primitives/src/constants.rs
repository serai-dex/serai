use core::time::Duration;

/// The target block time.
pub const TARGET_BLOCK_TIME: Duration = Duration::from_secs(6);

#[cfg_attr(not(test), expect(unused))]
const MINUTE: Duration = Duration::from_mins(1);
const HOUR: Duration = Duration::from_hours(1);
/// One day, as Serai considers it.
///
/// This is defined as exactly 24 hours, regardless of the context.
pub const DAY: Duration = HOUR.checked_mul(24).unwrap();
/// One week, as Serai considers it.
///
/// This is defined as exactly 7 days, as Serai considers a day, regardless of the context.
pub const WEEK: Duration = DAY.checked_mul(7).unwrap();

/// The intended duration for a session.
pub const SESSION_LENGTH: Duration = WEEK;
/// The intended duration for a session, represented in the amount of block proposal slots.
pub const SESSION_LENGTH_IN_SLOTS: u64 = SESSION_LENGTH.as_secs() / TARGET_BLOCK_TIME.as_secs();

/// The duration for which a retirement signal is locked in before the protocol retires,
/// represented in the amount of block proposal slots.
#[doc(hidden)]
pub const RETIREMENT_LOCK_IN_DURATION_IN_SLOTS: u64 =
  WEEK.checked_mul(4).unwrap().as_secs() / TARGET_BLOCK_TIME.as_secs();

#[test]
fn constants() {
  assert_eq!(MINUTE, Duration::from_secs(60));
  assert_eq!(HOUR, Duration::from_secs(60 * 60));
  assert_eq!(DAY, Duration::from_secs(24 * 60 * 60));
  assert_eq!(WEEK, Duration::from_secs(7 * 24 * 60 * 60));

  assert_eq!(SESSION_LENGTH, WEEK);

  assert_eq!(
    SESSION_LENGTH_IN_SLOTS,
    u64::try_from(SESSION_LENGTH.as_nanos() / TARGET_BLOCK_TIME.as_nanos()).unwrap()
  );
  assert_eq!(SESSION_LENGTH_IN_SLOTS, (7 * 24 * 60 * 60) / 6);

  assert_eq!(RETIREMENT_LOCK_IN_DURATION_IN_SLOTS, (4 * 7 * 24 * 60 * 60) / 6);
}
