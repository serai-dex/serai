use core::{num::NonZero, time::Duration};

#[cfg(feature = "std")]
use zeroize::Zeroize;

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "borsh")]
use borsh::{BorshSerialize, BorshDeserialize};
#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

use sp_core::{ConstU32, bounded::BoundedVec};
#[cfg(not(feature = "std"))]
use sp_std::vec::Vec;

use serai_primitives::{TARGET_BLOCK_TIME, Amount};

use crate::{SESSION_LENGTH, MAX_KEY_SHARES_PER_SET_U32};

/// Each slash point is equivalent to the downtime implied by missing a block proposal.
// Takes a NonZero<u16> so that the result is never 0.
fn downtime_per_slash_point(validators: NonZero<u16>) -> Duration {
  Duration::from_secs(TARGET_BLOCK_TIME) * u32::from(u16::from(validators))
}

/// A slash for a validator.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Zeroize))]
#[cfg_attr(feature = "borsh", derive(BorshSerialize, BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
  /// Does not panic, even due to overflows, if `allocated_stake + session_rewards <= u64::MAX`.
  pub fn penalty(
    self,
    validators: NonZero<u16>,
    allocated_stake: Amount,
    session_rewards: Amount,
  ) -> Amount {
    match self {
      Self::Points(slash_points) => {
        let mut slash_points = u64::from(slash_points);
        // Do the logic with the stake in u128 to prevent overflow from multiplying u64s
        let allocated_stake = u128::from(allocated_stake.0);
        let session_rewards = u128::from(session_rewards.0);

        // A Serai validator is allowed to be offline for an average of one day every two weeks
        // with no additional penalty. They'll solely not earn rewards for the time they were
        // offline.
        const GRACE_WINDOW: Duration = Duration::from_secs(2 * 7 * 24 * 60 * 60);
        const GRACE: Duration = Duration::from_secs(24 * 60 * 60);

        // GRACE / GRACE_WINDOW is the fraction of the time a validator is allowed to be offline
        // This means we want SESSION_LENGTH * (GRACE / GRACE_WINDOW), but with the parentheses
        // moved so we don't incur the floordiv and hit 0
        const PENALTY_FREE_DOWNTIME: Duration = Duration::from_secs(
          (SESSION_LENGTH.as_secs() * GRACE.as_secs()) / GRACE_WINDOW.as_secs(),
        );

        let downtime_per_slash_point = downtime_per_slash_point(validators);
        let penalty_free_slash_points =
          PENALTY_FREE_DOWNTIME.as_secs() / downtime_per_slash_point.as_secs();

        /*
          In practice, the following means:

          - Hours 0-12 are penalized as if they're hours 0-12.
          - Hours 12-24 are penalized as if they're hours 12-36.
          - Hours 24-36 are penalized as if they're hours 36-96.
          - Hours 36-48 are penalized as if they're hours 96-168.

          /* Commented, see below explanation of why.
          - Hours 48-168 are penalized for 0-2% of stake.
          - 168-336 hours of slashes, for a session only lasting 168 hours, is penalized for 2-10%
            of stake.

          This means a validator offline has to be offline for more than two days to start having
          their stake slashed.
          */

          This means a validator offline for two days will not earn any rewards for that session.
        */

        const MULTIPLIERS: [u64; 4] = [1, 2, 5, 6];
        let reward_slash = {
          // In intervals of the penalty-free slash points, weight the slash points accrued
          // The multiplier for the first interval is 1 as it's penalty-free
          let mut weighted_slash_points_for_reward_slash = 0;
          let mut total_possible_slash_points_for_rewards_slash = 0;
          for mult in MULTIPLIERS {
            let slash_points_in_interval = slash_points.min(penalty_free_slash_points);
            weighted_slash_points_for_reward_slash += slash_points_in_interval * mult;
            total_possible_slash_points_for_rewards_slash += penalty_free_slash_points * mult;
            slash_points -= slash_points_in_interval;
          }
          // If there are no penalty-free slash points, and the validator was slashed, slash the
          // entire reward
          (u128::from(weighted_slash_points_for_reward_slash) * session_rewards)
            .checked_div(u128::from(total_possible_slash_points_for_rewards_slash))
            .unwrap_or({
              if weighted_slash_points_for_reward_slash == 0 {
                0
              } else {
                session_rewards
              }
            })
        };
        // Ensure the slash never exceeds the amount slashable (due to rounding errors)
        let reward_slash = reward_slash.min(session_rewards);

        /*
        let slash_points_for_entire_session =
          SESSION_LENGTH.as_secs() / downtime_per_slash_point.as_secs();

        let offline_slash = {
          // The amount of stake to slash for being offline
          const MAX_STAKE_SLASH_PERCENTAGE_OFFLINE: u64 = 2;

          let stake_to_slash_for_being_offline =
            (allocated_stake * u128::from(MAX_STAKE_SLASH_PERCENTAGE_OFFLINE)) / 100;

          // We already removed the slash points for `intervals * penalty_free_slash_points`
          let slash_points_for_reward_slash =
            penalty_free_slash_points * u64::try_from(MULTIPLIERS.len()).unwrap();
          let slash_points_for_offline_stake_slash =
            slash_points_for_entire_session.saturating_sub(slash_points_for_reward_slash);

          let slash_points_in_interval = slash_points.min(slash_points_for_offline_stake_slash);
          slash_points -= slash_points_in_interval;
          // If there are no slash points for the entire session, don't slash stake
          // That's an extreme edge case which shouldn't start penalizing validators
          (u128::from(slash_points_in_interval) * stake_to_slash_for_being_offline)
            .checked_div(u128::from(slash_points_for_offline_stake_slash))
            .unwrap_or(0)
        };

        let disruptive_slash = {
          /*
            A validator may have more slash points than `slash_points_for_stake_slash` if they
            didn't just accrue slashes for missing block proposals, yet also accrued slashes for
            being disruptive. In that case, we still want to bound their slash points so they can't
            somehow be slashed for 100% of their stake (which should only happen on a fatal slash).
          */
          const MAX_STAKE_SLASH_PERCENTAGE_DISRUPTIVE: u64 = 8;

          let stake_to_slash_for_being_disruptive =
            (allocated_stake * u128::from(MAX_STAKE_SLASH_PERCENTAGE_DISRUPTIVE)) / 100;
          // Follows the offline slash for `unwrap_or` policy
          (u128::from(slash_points.min(slash_points_for_entire_session)) *
            stake_to_slash_for_being_disruptive)
            .checked_div(u128::from(slash_points_for_entire_session))
            .unwrap_or(0)
        };
        */

        /*
          We do not slash for being offline/disruptive at this time. Doing so allows an adversary
          to DoS nodes to not just take them offline, yet also take away their stake. This isn't
          preferable to the increased incentive to properly maintain a node when the rewards should
          already be sufficient for that purpose.

          Validators also shouldn't be able to be so disruptive due to their limiting upon
          disruption *while its ongoing*. Slashes as a post-response, while an arguably worthwhile
          economic penalty, can never be a response in the moment (as necessary to actually handle
          the disruption).

          If stake slashing was to be re-enabled, the percentage of stake which is eligible for
          slashing should be variable to how close we are to losing liveness. This would mean if
          less than 10% of validators are offline, no stake is slashes. If 10% are, 2% is eligible.
          If 20% are, 5% is eligible. If 30% are, 10% is eligible.

          (or similar)

          This would mean that a DoS is insufficient to cause a validator to lose their stake.
          Instead, a coordinated DoS against multiple Serai validators would be needed,
          strengthening our assumptions.
        */
        let offline_slash = 0;
        let disruptive_slash = 0;

        let stake_slash = (offline_slash + disruptive_slash).min(allocated_stake);

        let penalty_u128 = reward_slash + stake_slash;
        // saturating_into
        Amount(u64::try_from(penalty_u128).unwrap_or(u64::MAX))
      }
      // On fatal slash, their entire stake is removed
      Self::Fatal => Amount(allocated_stake.0 + session_rewards.0),
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SlashReport(pub BoundedVec<Slash, ConstU32<{ MAX_KEY_SHARES_PER_SET_U32 }>>);

#[cfg(feature = "borsh")]
impl BorshSerialize for SlashReport {
  fn serialize<W: borsh::io::Write>(&self, writer: &mut W) -> borsh::io::Result<()> {
    BorshSerialize::serialize(self.0.as_slice(), writer)
  }
}
#[cfg(feature = "borsh")]
impl BorshDeserialize for SlashReport {
  fn deserialize_reader<R: borsh::io::Read>(reader: &mut R) -> borsh::io::Result<Self> {
    let slashes = Vec::<Slash>::deserialize_reader(reader)?;
    slashes
      .try_into()
      .map(Self)
      .map_err(|_| borsh::io::Error::other("length of slash report exceeds max validators"))
  }
}

impl TryFrom<Vec<Slash>> for SlashReport {
  type Error = &'static str;
  fn try_from(slashes: Vec<Slash>) -> Result<SlashReport, &'static str> {
    slashes.try_into().map(Self).map_err(|_| "length of slash report exceeds max validators")
  }
}

impl SlashReport {
  /// The message to sign when publishing this SlashReport.
  // This is assumed binding to the ValidatorSet via the key signed with
  pub fn report_slashes_message(&self) -> Vec<u8> {
    (b"ValidatorSets-report_slashes", &self.0).encode()
  }
}

#[test]
fn test_penalty() {
  for validators in [1, 50, 100, crate::MAX_KEY_SHARES_PER_SET] {
    let validators = NonZero::new(validators).unwrap();
    // 12 hours of slash points should only decrease the rewards proportionately
    let twelve_hours_of_slash_points =
      u32::try_from((12 * 60 * 60) / downtime_per_slash_point(validators).as_secs()).unwrap();
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

    /*
    // A full week of slash points should slash 2%
    let week_of_slash_points = 14 * twelve_hours_of_slash_points;
    assert_eq!(
      Slash::Points(week_of_slash_points).penalty(validators, Amount(1000), Amount(168)),
      Amount(20 + 168)
    );

    // Two weeks of slash points should slash 10%
    assert_eq!(
      Slash::Points(2 * week_of_slash_points).penalty(validators, Amount(1000), Amount(168)),
      Amount(100 + 168)
    );

    // Anything greater should still only slash 10%
    assert_eq!(
      Slash::Points(u32::MAX).penalty(validators, Amount(1000), Amount(168)),
      Amount(100 + 168)
    );
    */

    // Anything greater should still only slash the rewards
    assert_eq!(
      Slash::Points(u32::MAX).penalty(validators, Amount(u64::MAX), Amount(168)),
      Amount(168)
    );
  }
}

#[test]
fn no_overflow() {
  Slash::Points(u32::MAX).penalty(
    NonZero::new(u16::MAX).unwrap(),
    Amount(u64::MAX),
    Amount(u64::MAX),
  );

  Slash::Points(u32::MAX).penalty(NonZero::new(1).unwrap(), Amount(u64::MAX), Amount(u64::MAX));
}
