use core::{num::NonZero, time::Duration};
use alloc::vec::Vec;

use zeroize::Zeroize;

use borsh::{BorshSerialize, BorshDeserialize};

use sp_core::{ConstU32, bounded::BoundedVec};

use crate::{
  constants::{TARGET_BLOCK_TIME, SESSION_LENGTH},
  balance::Amount,
  validator_sets::KeyShares,
};

/// Each slash point is equivalent to the downtime implied by missing a block proposal.
// Takes a NonZero<u16> so that the result is never 0, making this safe to divide by.
fn downtime_per_slash_point(validators: NonZero<u16>) -> Duration {
  TARGET_BLOCK_TIME * u32::from(u16::from(validators))
}

/// A slash for a validator.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub enum Slash {
  /// The slash points accumulated by this validator.
  ///
  /// Each point is considered as `downtime_per_slash_point(validators)` downtime, where
  /// `validators` is the amount of validators present in the set.
  Points(u32),
  /// A fatal slash due to fundamentally faulty behavior.
  ///
  /// This should only be used for misbehavior with explicit evidence of impropriety. This should
  /// not be used for liveness failures. The validator will be penalized all allocated stake.
  Fatal,
}

impl Slash {
  /// Calculate the penalty which should be applied to the validator.
  ///
  /// The returned penalty is _inclusive_ of the rewards which should be distributed. This means
  /// the rewards should be distributed before the penalty is applied, or the penalty should be
  /// taken from the rewards before any remainder is taken from the allocated stake.
  ///
  /// Pervasive downtime will cause a validator to lose rewards, but will not slash their stake.
  /// If stake were to be slashed, an adversary who performs a DoS against nodes would not only be
  /// able to taken them offline yet also burn their stake. Granting an adversary this power isn't
  /// prefereable to the risk of offline nodes remaining offline (without additional penalty), as
  /// the rewards are intended to be sufficient incentive for them to be online and stay online in
  /// the first place.
  ///
  /// This function is expected not to panic, even when compiled with checked arithmetic and given
  /// arbitrary values. If the penalty exceeds `u64::MAX`, it will saturate into `u64::MAX`, so the
  /// caller must ensure `(allocated_stake + session_rewards) <= u64::MAX` for this value to remain
  /// correct.
  pub fn penalty(
    self,
    validators: NonZero<u16>,
    allocated_stake: Amount,
    session_rewards: Amount,
  ) -> Amount {
    match self {
      Self::Points(slash_points) => {
        let mut slash_points = u64::from(slash_points);
        // Do the logic with the stake in `u128` to prevent overflow from multiplying `u64`s
        let session_rewards = u128::from(session_rewards.0);

        // A Serai validator is allowed to be offline for an average of one day every two weeks
        // with no additional penalty. They'll solely not earn rewards for the time they were
        // offline.
        const GRACE_WINDOW: Duration = crate::constants::WEEK.checked_mul(2).unwrap();
        const GRACE: Duration = crate::constants::DAY;

        // `GRACE / GRACE_WINDOW` is the fraction of the time a validator is allowed to be offline
        // This means we want `SESSION_LENGTH * (GRACE / GRACE_WINDOW)`, but with the parentheses
        // moved so we don't incur the floordiv and hit 0
        const PENALTY_FREE_DOWNTIME: Duration = Duration::from_secs(
          (SESSION_LENGTH.as_secs() * GRACE.as_secs()) / GRACE_WINDOW.as_secs(),
        );

        let downtime_per_slash_point = downtime_per_slash_point(validators);
        // This uses `div_ceil` so the points here round to be at least for the
        // intended penalty-free downtime
        let penalty_free_slash_points =
          PENALTY_FREE_DOWNTIME.as_secs().div_ceil(downtime_per_slash_point.as_secs());

        /*
          In practice, the following means:

          - Hours 0-12 are penalized as if they're hours 0-12.
          - Hours 12-24 are penalized as if they're hours 12-36.
          - Hours 24-36 are penalized as if they're hours 36-96.
          - Hours 36-48 are penalized as if they're hours 96-168.

          This means a validator offline for two days will not earn any rewards for that session.
        */

        const MULTIPLIERS: [u64; 4] = [1, 2, 5, 6];
        let reward_slash = {
          // In intervals of the penalty-free slash points, weight the slash points accrued
          // The multiplier for the first interval is 1 as it's penalty-free
          let mut weighted_slash_points_for_reward_slash = 0;
          let mut slash_points_considered_for_rewards_slash = 0;
          for mult in MULTIPLIERS {
            let slash_points_in_interval = slash_points.min(penalty_free_slash_points);
            weighted_slash_points_for_reward_slash += slash_points_in_interval * mult;
            slash_points_considered_for_rewards_slash += penalty_free_slash_points * mult;
            slash_points -= slash_points_in_interval;
          }

          // Slash an amount of rewards corresponding to the validator's weighted downtime
          let reward_slash = (u128::from(weighted_slash_points_for_reward_slash) * session_rewards)
            .checked_div(u128::from(slash_points_considered_for_rewards_slash));

          /*
            This `unwrap_or` is unreachable if
            `slash_points_considered_for_rewards_slash != 0`. If it was `0`, then a binary choice
            is present. Either,
            A) The validator had no slash points.
            B) The validator had more slash points than we were willing to consider.
            For the former, we don't slash at all. For the latter, we slash the entire session.
          */
          reward_slash.unwrap_or({
            if weighted_slash_points_for_reward_slash == 0 { 0 } else { session_rewards }
          })
        };
        // Ensure the slash never exceeds the amount slashable (due to rounding errors)
        let reward_slash = reward_slash.min(session_rewards);

        // saturating_into
        Amount(u64::try_from(reward_slash).unwrap_or(u64::MAX))
      }
      // On fatal slash, their entire stake is removed
      Self::Fatal => Amount(allocated_stake.0.saturating_add(session_rewards.0)),
    }
  }
}

/// A report of all slashes incurred for a `ValidatorSet`.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct SlashReport(
  #[borsh(
    serialize_with = "crate::borsh_serialize_bounded_vec",
    deserialize_with = "crate::borsh_deserialize_bounded_vec"
  )]
  pub BoundedVec<Slash, ConstU32<{ KeyShares::MAX_PER_SET_U32 }>>,
);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(SlashReport);

/// An error when converting from a `Vec`.
#[derive(Debug)]
pub enum FromVecError {
  /// The source `Vec` was too long to be converted.
  TooLong,
}

impl TryFrom<Vec<Slash>> for SlashReport {
  type Error = FromVecError;
  fn try_from(slashes: Vec<Slash>) -> Result<SlashReport, FromVecError> {
    slashes.try_into().map(Self).map_err(|_| FromVecError::TooLong)
  }
}

impl zeroize::Zeroize for SlashReport {
  fn zeroize(&mut self) {
    for slash in self.0.as_mut() {
      slash.zeroize();
    }
  }
}

impl SlashReport {
  /// The message to sign when publishing this SlashReport.
  // This is assumed binding to the ValidatorSet via the key signed with
  pub fn report_slashes_message(&self) -> Vec<u8> {
    const DST: &[u8] = b"ValidatorSets-report_slashes";
    let mut buf = Vec::with_capacity(
      DST.len() + core::mem::size_of::<u32>() + (self.0.len() * core::mem::size_of::<Slash>()),
    );
    (DST, self).serialize(&mut buf).unwrap();
    buf
  }
}

#[test]
fn serialize() {
  use alloc::vec;
  use rand_core::{RngCore as _, OsRng};

  // Fuzz test various `SlashReport`s
  for i in 0 ..= KeyShares::MAX_PER_SET {
    let mut report = vec![];
    for _ in 0 .. i {
      #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
      report.push(if (OsRng.next_u64() % 2) == 1 {
        Slash::Points(OsRng.next_u64() as u32)
      } else {
        Slash::Fatal
      });
    }
    let slash_report = SlashReport::try_from(report).unwrap();

    assert_eq!(
      SlashReport::deserialize_reader(&mut borsh::to_vec(&slash_report).unwrap().as_slice())
        .unwrap(),
      slash_report
    );

    #[cfg(feature = "scale")]
    use scale::{Encode as _, DecodeAll as _};
    #[cfg(feature = "scale")]
    assert_eq!(
      SlashReport::decode_all(&mut borsh::to_vec(&slash_report).unwrap().as_slice()).unwrap(),
      slash_report
    );
    #[cfg(feature = "scale")]
    assert_eq!(
      SlashReport::deserialize_reader(&mut slash_report.encode().as_slice()).unwrap(),
      slash_report
    );
  }
}

#[test]
fn test_penalty() {
  for validators in [1, 50, 100, KeyShares::MAX_PER_SET] {
    let validators = NonZero::new(validators).unwrap();
    // 12 hours of slash points should only decrease the rewards proportionately
    let twelve_hours_of_slash_points =
      u32::try_from((12u64 * 60 * 60).div_ceil(downtime_per_slash_point(validators).as_secs()))
        .unwrap();
    assert_eq!(
      Slash::Points(twelve_hours_of_slash_points).penalty(
        validators,
        Amount(u64::MAX),
        Amount(168)
      ),
      Amount(12)
    );
    // 24 hours of slash points should be counted as 36 hours
    assert_eq!(
      Slash::Points(2 * twelve_hours_of_slash_points).penalty(
        validators,
        Amount(u64::MAX),
        Amount(168)
      ),
      Amount(36)
    );
    // 36 hours of slash points should be counted as 96 hours
    assert_eq!(
      Slash::Points(3 * twelve_hours_of_slash_points).penalty(
        validators,
        Amount(u64::MAX),
        Amount(168)
      ),
      Amount(96)
    );
    // 48 hours of slash points should be counted as 168 hours
    assert_eq!(
      Slash::Points(4 * twelve_hours_of_slash_points).penalty(
        validators,
        Amount(u64::MAX),
        Amount(168)
      ),
      Amount(168)
    );

    // Anything greater should still only slash the rewards
    assert_eq!(
      Slash::Points(u32::MAX).penalty(validators, Amount(u64::MAX), Amount(168)),
      Amount(168)
    );

    // Except for a fatal slash
    assert_eq!(
      Slash::Fatal.penalty(validators, Amount(1_000_000), Amount(1_000)),
      Amount(1_001_000)
    );
  }
}

#[test]
fn no_overflow() {
  // Test with u16::MAX for validators, maximizing the downtime each slash point represents
  Slash::Points(u32::MAX).penalty(
    NonZero::new(u16::MAX).unwrap(),
    Amount(u64::MAX),
    Amount(u64::MAX),
  );

  // Test with 1 for validators, in case validators is inversely correlated
  Slash::Points(u32::MAX).penalty(NonZero::new(1).unwrap(), Amount(u64::MAX), Amount(u64::MAX));

  // Fuzz test with random values
  for _ in 0 .. 100 {
    use rand_core::{RngCore as _, OsRng};
    #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
    let _ = Slash::Points(OsRng.next_u64() as u32).penalty(
      NonZero::new(OsRng.next_u64() as u16).unwrap(),
      Amount(OsRng.next_u64()),
      Amount(OsRng.next_u64()),
    );
  }
}
