use core::time::Duration;
use std::time::{Instant, SystemTime};

use crate::{SignatureScheme, ValidRound};

use super::{Borshy, BorshyBlockchain};

serai_db::schema!(TributaryState {
  BlockNumber: (genesis: &[u8]) -> crate::BlockNumber,

  RoundNumber: (genesis: &[u8]) -> crate::RoundNumber,
  PendingStepTimeout: (genesis: &[u8]) -> u64,
  PendingPrecommitTimeout: (genesis: &[u8]) -> u64,
  Step: (genesis: &[u8]) -> super::Step,

  Valid: <B: BorshyBlockchain>(genesis: &[u8]) -> (
    ValidRound<<B::SignatureScheme as SignatureScheme>::AggregateSignature>,
    B::Block
  ),

  Locked: <Hash: Borshy>(genesis: &[u8]) -> (crate::RoundNumber, Hash),

  OurLatestPrevotes: <B: BorshyBlockchain>(genesis: &[u8]) -> [Option<crate::MessageFor<B>>; 2],
  OurLatestPrecommit: <B: BorshyBlockchain>(genesis: &[u8]) -> crate::MessageFor<B>,
});

pub(super) fn timeout_in_ms_since_epoch(timeout: Duration) -> u64 {
  let expiry = SystemTime::now().checked_add(timeout);
  /*
    If this expiry was representable, continue by taking its duration since the epoch.

    If it expires before the epoch, meaning now is before the epoch, this is below our least
    representable time. We unwrap to `Duration::ZERO`, our lowest representable time, accordingly.
  */
  let expiry_from_epoch =
    expiry.map(|expiry| expiry.duration_since(SystemTime::UNIX_EPOCH).unwrap_or(Duration::ZERO));
  /*
    If the expiry wasn't representable, meanining it overflowed the `SystemTime`, unwrap to the
    greatest duration possible.
  */
  let expiry_in_ms_since_epoch = expiry_from_epoch.unwrap_or(Duration::MAX);
  // Perform a saturating conversion into a `u64`
  u64::try_from(expiry_in_ms_since_epoch.as_millis()).unwrap_or(u64::MAX)
}

pub(super) fn timeout_from_ms_since_epoch(ms: u64) -> (Instant, Duration) {
  let start = Instant::now();

  /*
    This explicitly calculates the duration from a `SystemTime` sampled _after_ the `Instant` is
    sampled, such that the `Duration` we return should actually be _less_ than the
    perfectly-correct value (as calculated since from the `Instant` we sampled).

    We have to attempt to be less or more, due to the fact these aren't perfectly synchronized.

    We pick being less so this if timeout triggered, and then we crashed, this timeout will
    presumably immediately trigger on reboot. If this timeout was _greater_ than it was prior, on
    reboot, we may handle a message (changing our state) before this timeout expires. While
    either SHOULD be fine, the implied greater consistency of being less is preferable.

    Similarly, when we set timeouts, we always save the timeout _before_ sampling the `Instant`.

    While this arguably just flips the problem, where we crashed during an incoming message and
    on reboot, may handle a timeout instead of the message, the timeout logic is more complicated
    and hence why the logic we prefer to ensure is less likely to suffer such inconsistencies.
    Again though, the overall database design SHOULD make this irrelevant.
  */
  let duration = match SystemTime::UNIX_EPOCH.checked_add(Duration::from_millis(ms)) {
    Some(expiry) => expiry.duration_since(SystemTime::now()).unwrap_or(Duration::ZERO),
    None => Duration::MAX,
  };

  (start, duration)
}

#[test]
fn unix_time() {
  for _ in 0 .. 128 {
    #[allow(clippy::duration_suboptimal_units)] // TODO: `expect`
    let timeout = Duration::from_millis(1000);

    let unix_time_in_ms = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_millis();
    let fetched_unix_time = timeout_in_ms_since_epoch(timeout);
    let actual_timeout_start = Instant::now();
    let unix_time_in_ms_now = SystemTime::UNIX_EPOCH.elapsed().unwrap().as_millis();
    // Check those lines took less than 100ms to run
    assert!((unix_time_in_ms_now - unix_time_in_ms) < 100);

    assert!((unix_time_in_ms + 1000) <= u128::from(fetched_unix_time));
    assert!(u128::from(fetched_unix_time) <= (unix_time_in_ms_now + 1000));

    let (now, time_remaining) = timeout_from_ms_since_epoch(fetched_unix_time);
    let actual_time_remaining =
      timeout.checked_sub(now.duration_since(actual_timeout_start)).unwrap();
    // The reloaded timeout is expected to be slightly shorter than the honest timeout
    assert!(time_remaining < actual_time_remaining);
    // but it should be approximate
    assert!(actual_time_remaining <= (time_remaining + Duration::from_millis(100)));
  }
}
