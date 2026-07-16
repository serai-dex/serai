use core::time::Duration;
use std::time::{Instant, SystemTime};

use crate::{Borshy, SignatureScheme, ValidRound, Block, Blockchain};

trait BorshyBlockchain: Blockchain<Block: Borshy + Block<Hash: Borshy>> {}
impl<B: Blockchain<Block: Borshy + Block<Hash: Borshy>>> BorshyBlockchain for B {}

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

  OurLatestMessage: <B: BorshyBlockchain>(genesis: &[u8]) -> crate::MessageFor<B>,
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
