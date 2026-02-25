#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

//! `spec/Emissions.md` details itself in terms of block rewards. Here, it should be noted that
//! the Serai validators earn a reward per slot (in order to cause those who are offline and don't
//! propose blocks to not receive rewards), but the external validator sets operate on the amount
//! of _time_ which has passed. This achieves a more stable stream of emissions for those
//! independent of responsibilty for producing blocks on a regular schedule. Regardless, when
//! considering the block reward as emissions per slot, the total emissions should still be as
//! expected.

use core::time::Duration;
extern crate alloc;
use alloc::{vec, vec::Vec};

use serai_abi::primitives::{constants, coin::Coin, balance::Amount};

mod post_economic_security;

#[cfg(test)]
mod tests;

const DAYS_365: Duration = constants::DAY.checked_mul(365).unwrap();

const INITIAL_PERIOD: Duration = constants::DAY.checked_mul(30).unwrap();
const INITIAL_PERIOD_REWARDS_PER_DAY: Amount = Amount(100_000 * 10u64.pow(Coin::Serai.decimals()));
#[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
const INITIAL_PERIOD_REWARDS: Amount = Amount(
  (((INITIAL_PERIOD_REWARDS_PER_DAY.0 as u128) * INITIAL_PERIOD.as_millis()) /
    constants::DAY.as_millis()) as u64,
);
#[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
const INITIAL_PERIOD_REWARD_PER_BLOCK: Amount = Amount(
  (((INITIAL_PERIOD_REWARDS.0 as u128) * constants::TARGET_BLOCK_TIME.as_millis()) /
    INITIAL_PERIOD.as_millis()) as u64,
);
const SECURE_BY: Duration = DAYS_365;

const POST_ECONOMIC_SECURITY_REWARDS_PER_365_DAYS: Amount =
  Amount(20_000_000 * 10u64.pow(Coin::Serai.decimals()));
#[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
const POST_ECONOMIC_SECURITY_REWARD_PER_BLOCK: Amount = Amount(
  (((POST_ECONOMIC_SECURITY_REWARDS_PER_365_DAYS.0 as u128) *
    constants::TARGET_BLOCK_TIME.as_millis()) /
    DAYS_365.as_millis()) as u64,
);

#[expect(let_underscore_drop)]
#[frame_support::pallet]
mod pallet {
  use frame_support::{pallet_prelude::*, traits::PreInherents};
  use frame_system::pallet_prelude::BlockNumberFor;

  use serai_abi::{
    primitives::{network_id::*, coin::ExternalCoin, balance::Balance, validator_sets::*},
    economic_security::EconomicSecurity,
    TransactionContext as _,
  };

  use super::*;

  /// Methods from [`serai_validator_sets_pallet::Pallet`] which [`Pallet`] requires.
  ///
  /// This is behind a `trait` to allow shimming it when testing. For the exact description, and
  /// bounds, of these methods, please refer to [`serai_validator_sets_pallet::Pallet`].
  pub trait ValidatorSets {
    /// The latest decided session for a network.
    fn latest_decided_session(network: NetworkId) -> Option<Session>;
    /// The total amount of stake allocated for this network.
    fn total_allocated_stake_for_network(network: NetworkId) -> Amount;
    /// The stake for the latest decided validator set for a network.
    fn stake_for_latest_decided_validator_set(network: NetworkId) -> Option<Amount>;
    /// If a validator set's rewards have been distributed.
    ///
    /// This is not present directly in `serai_validator_sets_pallet` and is bespoke to this
    /// interface.
    fn rewards_distributed_for_set(set: ExternalValidatorSet) -> bool;
  }

  impl<T: serai_validator_sets_pallet::Config> ValidatorSets
    for serai_validator_sets_pallet::Pallet<T>
  {
    fn latest_decided_session(network: NetworkId) -> Option<Session> {
      Self::latest_decided_session(network)
    }
    fn total_allocated_stake_for_network(network: NetworkId) -> Amount {
      Self::total_allocated_stake_for_network(network)
    }
    fn stake_for_latest_decided_validator_set(network: NetworkId) -> Option<Amount> {
      Self::stake_for_latest_decided_validator_set(network)
    }
    fn rewards_distributed_for_set(set: ExternalValidatorSet) -> bool {
      /*
        `serai-validator-sets-pallet` distributes rewards for an external validator set upon
        publication of its slash report. We require the set be retired, and therefore eligible to
        publish a slash report, and to no longer have its slash report pending, implying
        distribution of rewards, to satisfy the API here.

        Note that internally to `serai-validator-sets-pallet`, failure to submit a slash report in
        a timely fashion will effect no rewards to be distributed. For the purposes of the API
        here, no rewards being distributed is functionally equivalent to distributing `0`.
      */
      (Self::current_session(set.network.into()) > Some(set.session)) &&
        (!Self::pending_slash_report(set))
    }
  }

  /// The configuration of this pallet.
  #[pallet::config]
  pub trait Config:
    frame_system::Config
    + serai_core_pallet::Config
    + serai_coins_pallet::Config<serai_coins_pallet::CoinsInstance>
    + serai_coins_pallet::Config<serai_coins_pallet::LiquidityTokensInstance>
    + serai_dex_pallet::Config
  {
    /// The validator sets pallet.
    type ValidatorSets: ValidatorSets;
    /// The economic security oracle.
    type EconomicSecurity: EconomicSecurity;
  }

  /// If a prior validator set for every network has achieved economic set.
  #[pallet::storage]
  type PriorAchievedEconomicSecurity<T: Config> = StorageValue<_, (), OptionQuery>;

  /// Determine if we've reached economic security.
  ///
  /// This will return `true` if we have and `false` if we haven't. This will also prepare the
  /// relevant storage for post-Economic Security upon determining we've reached economic security.
  fn determine_if_post_economic_security<T: Config>() -> bool {
    if PriorAchievedEconomicSecurity::<T>::get().is_some() {
      return true;
    }

    if ExternalNetworkId::all().all(T::EconomicSecurity::achieved_economic_security) {
      PriorAchievedEconomicSecurity::<T>::set(Some(()));
      for coin in ExternalCoin::all() {
        // Drop the tally of all fees burnt pre-Economic Security
        let _ = serai_dex_pallet::Pallet::<T>::take_burnt_fees(coin);
      }
      return true;
    }

    false
  }

  /// The time of the last block.
  #[pallet::storage]
  type TimeOfLastBlock<T: Config> = StorageValue<_, u64, OptionQuery>;

  #[pallet::hooks] // serai-core-pallet: allow
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_finalize(_block_number: BlockNumberFor<T>) {
      TimeOfLastBlock::<T>::set(Some(serai_core_pallet::Pallet::<T>::current_time()));
    }
  }

  /// The time from the block where the pools were initialized.
  #[pallet::storage]
  pub(crate) type EndOfGenesisTimestamp<T: Config> = StorageValue<_, u64, OptionQuery>;
  /// Rewards for an external validator set.
  #[pallet::storage]
  pub(crate) type ExternalValidatorSetRewards<T: Config> =
    StorageMap<_, Identity, ExternalValidatorSet, Amount, ValueQuery>;
  /// Historical rewards for external validator sets.
  #[pallet::storage]
  pub(crate) type HistoricalExternalValidatorSetRewards<T: Config> =
    StorageMap<_, Identity, ExternalValidatorSet, Amount, ValueQuery>;

  /// Calculate a network's distance to economic security.
  ///
  /// `None` signifies the network having not decided a session or an overflow having occurred. In
  /// either case, we cannot represent the distance as an `Amount` as it's either `null` or out of
  /// range.
  fn distance_to_economic_security<T: Config>(network: ExternalNetworkId) -> Option<Amount> {
    if T::EconomicSecurity::achieved_economic_security(network) {
      return Some(Amount(0));
    }

    let achieved = {
      // If this validator set hasn't had a session decided, we say it has no distance
      let latest_decided_session = T::ValidatorSets::latest_decided_session(network.into())?;

      // The achieved stake is the sum of the allocated stake _and queued rewards_
      let mut achieved = Some(T::ValidatorSets::total_allocated_stake_for_network(network.into()));
      // We check _all historical sessions_ for rewards which have yet to be distributed
      for session in latest_decided_session.0.saturating_sub(4) ..= latest_decided_session.0 {
        let set = ExternalValidatorSet { network, session: Session(session) };
        // If the rewards _have_ been distributed, clean up the storage entry
        if T::ValidatorSets::rewards_distributed_for_set(set) {
          HistoricalExternalValidatorSetRewards::<T>::remove(set);
          continue;
        }
        /*
          Append pending rewards to the amount of stake this set has achieved.

          Note these values may not be set, yet the usage of a `ValueQuery` will cause this to get
          `Amount(0)` in such cases, which is fine. We also will only have one of these, if either,
          set at any moment within the pallet.
        */
        achieved = achieved
          .and_then(|achieved| achieved + HistoricalExternalValidatorSetRewards::<T>::get(set));
        achieved =
          achieved.and_then(|achieved| achieved + ExternalValidatorSetRewards::<T>::get(set));
      }
      achieved?
    };
    let stake_required =
      serai_validator_sets_pallet::network_stake_requirement::<T, T::EconomicSecurity>(network);
    // If this overflowed, return `None`
    if stake_required == Amount(u64::MAX) {
      None?;
    }
    Some(Amount(stake_required.0.saturating_sub(achieved.0)))
  }

  fn calculate_pre_economic_security_external_set_rewards<T: Config>(
    network: ExternalNetworkId,
  ) -> Amount {
    let Some(end_of_genesis) = EndOfGenesisTimestamp::<T>::get() else {
      // No rewards are emitted during the genesis period
      return Amount(0);
    };

    // If the requirement overflowed, we NOP here and issue a `0` reward
    let Some(our_distance) = distance_to_economic_security::<T>(network) else { return Amount(0) };

    let current_time = serai_core_pallet::Pallet::<T>::current_time();
    let time_of_last_block =
      TimeOfLastBlock::<T>::get().expect("taking reward for set on genesis block");
    let time_to_consider_rewards_for =
      current_time.checked_sub(time_of_last_block).expect("Serai timestamps are monotonic");

    // If this is within the initial period, the block reward is fixed
    if u128::from(current_time) < (u128::from(end_of_genesis) + INITIAL_PERIOD.as_millis()) {
      /*
        This inlines the literal `SERAI_VALIDATORS_DESIRED_PERCENTAGE` to determine the rewards
        which will go to the Serai validators, and from there, the rewards for the external
        networks.

        `time_to_consider_rewards_for` MUST be less than `INITIAL_PERIOD` as else we wouldn't be
        in the initial period. `INITIAL_PERIOD` MUST be non-zero as else, again, we wouldn't be
        in the initial period.

        The result will fit in a `u64` as `INITIAL_PERIOD_REWARDS` does and we scaled by a
        fraction less than or equal to `1`.
      */
      let external_network_rewards = Amount(
        u64::try_from(
          (u128::from(INITIAL_PERIOD_REWARDS.0 - (INITIAL_PERIOD_REWARDS.0 / 5)) *
            u128::from(time_to_consider_rewards_for)) /
            INITIAL_PERIOD.as_millis(),
        )
        .unwrap(),
      );

      // We distribute to each set based on their relative distances to security
      let mut total_distance = Amount(0);
      for network in ExternalNetworkId::all() {
        // NOP due to overflow
        let Some(this_distance) = distance_to_economic_security::<T>(network) else {
          return Amount(0);
        };
        // NOP due to overflow
        let Some(new_total_distance) = total_distance + this_distance else { return Amount(0) };
        total_distance = new_total_distance;
      }

      let Some(reward) = (u128::from(external_network_rewards.0) * u128::from(our_distance.0))
        .checked_div(u128::from(total_distance.0))
      else {
        // if the total distance is `0`, yield a reward of `0`
        return Amount(0);
      };
      // our distance will be a fraction of the total, and the reward itself fit in a `u64`
      return Amount(u64::try_from(reward).unwrap());
    }

    // This defines `time_since_genesis` relative to `time_of_last_block` as we want to know, for
    // the amount of time which has passed since the last block, what fraction of remaining time
    // has passed and how much of the distance we should close accordingly.
    let time_since_genesis =
      time_of_last_block.checked_sub(end_of_genesis).expect("Serai timestamps are monotonic");
    let time_until_secure_by = SECURE_BY.as_millis().saturating_sub(u128::from(time_since_genesis));

    /*
      If the rewards calculated exceed the distance, minimize to the distance, which ensures the
      result fits within an `Amount` (as our distance does).

      If `time_until_secure_by == 0`, in that the `SECURE_BY` deadline has passed but we have yet
      to achieve economic security (due to an unstable clock, slashes, other misc behavior), we set
      the rewards to the remainder of the distance.
    */
    (u128::from(our_distance.0) * u128::from(time_to_consider_rewards_for))
      .checked_div(time_until_secure_by)
      .map(|rewards| Amount(u64::try_from(rewards.max(u128::from(our_distance.0))).unwrap()))
      .unwrap_or(our_distance)
  }

  /// Effect the post-Economic Security rewards for external networks.
  ///
  /// This will _return_ the list of amounts to reward the validator sets with. These amounts will
  /// be ordered corresponding to [`ExternalNetworkId::all`]'s order of iteration.
  #[must_use]
  fn effect_post_economic_security_external_network_rewards<T: Config>() -> Vec<Amount> {
    let mut total_burnt_fees = 0u128;
    let mut burnt_fees_by_network = vec![];
    for network in ExternalNetworkId::all() {
      let mut burnt_fees_for_network = 0u128;
      let mut burnt_fees_by_coin = vec![];
      for coin in network.coins() {
        let burnt_fees_for_coin: u128 = serai_dex_pallet::Pallet::<T>::take_burnt_fees(coin);
        // This won't overflow as individual fee burns are `u64` but this accumulator is a
        // `u128`, requiring `2**64` fee burns to occur in a single block to overflow
        total_burnt_fees += burnt_fees_for_coin;
        burnt_fees_by_coin.push(burnt_fees_for_coin);
        burnt_fees_for_network += burnt_fees_for_coin;
      }
      burnt_fees_by_network.push((burnt_fees_for_network, burnt_fees_by_coin));
    }

    let current_time = serai_core_pallet::Pallet::<T>::current_time();
    let time_of_last_block =
      TimeOfLastBlock::<T>::get().expect("post-Economic Security on the very first block?");
    let time_to_consider_rewards_for =
      current_time.checked_sub(time_of_last_block).expect("Serai timestamps are monotonic");
    /*
      This inlines `SERAI_VALIDATORS_DESIRED_PERCENTAGE` in order to calculate what percentage of
      the block rewards go to Serai validators, and from there, how much go to the validators for
      external networks.

      This will itself fit in a `u64` if the time between two blocks is less than a year, which can
      be assumed without issue as else the network has much larger problems. Even then, it'd have
      to be `u64::MAX / POST_ECONOMIC_SECURITY_REWARDS_PER_365_DAYS` years...
    */
    let external_network_rewards = u64::try_from(
      (u128::from(
        POST_ECONOMIC_SECURITY_REWARDS_PER_365_DAYS.0 -
          (POST_ECONOMIC_SECURITY_REWARDS_PER_365_DAYS.0 / 5),
      ) * u128::from(time_to_consider_rewards_for)) /
        DAYS_365.as_millis(),
    )
    .expect("time between blocks exceeded one year");

    let mut result = vec![];
    for (network, (burnt_fees_for_network, burnt_fees_by_coin)) in
      ExternalNetworkId::all().zip(burnt_fees_by_network)
    {
      /*
        Note this methodology actually enables a form of arbitrage such that if the cost to burn
        fees within a pool is sufficiently low, it can be worth more by the increased amount of
        rewards which will be distributed to the pool. This is actually beneficial for Serai as if
        Serai is distributing too much SRI in rewards, 'adversaries' have incentive to
        _perform burns themselves for their profit_, reducing the overall SRI supply compared to if
        they did nothing.

        While it is arguably hostile to other pools, all users within a pool are still treated
        equally and any pool can have an entity perform this arbitrage for it, so it's as level a
        playing field as Serai inherently is.
      */
      let rewards_for_network = (sp_core::U256::from(u128::from(external_network_rewards)) *
        sp_core::U256::from(burnt_fees_for_network))
      .checked_div(sp_core::U256::from(total_burnt_fees))
      .map(|amount| u64::try_from(amount).expect("`burnt_fees_for_network > total_burnt_fees`?"))
      .unwrap_or(0);

      let validators_fraction = {
        /*
          Note this may be `u64::MAX` if an overflow occurred. In that case, we still use it as-is
          because the methodology within
          `post_economic_security::external_network_validator_rewards_fraction` will bound it to be
          at most `capacity_of_network` (used capacity is `<=` actual capacity).
        */
        let used_capacity =
          serai_validator_sets_pallet::network_stake_requirement::<T, T::EconomicSecurity>(network);
        /*
          We use the capacity of the latest decided set as:
          - It will take over, so its economic security we primarily care about.
          - The latest decided set will receive these fees, for reasons described below.
        */
        let capacity_of_network =
          T::ValidatorSets::stake_for_latest_decided_validator_set(network.into())
            .unwrap_or(Amount(0));
        post_economic_security::external_network_validator_rewards_fraction(
          used_capacity,
          capacity_of_network,
        )
      };
      /*
        This won't overflow as the fraction's components are bounded to be `<= u192::MAX` and
        we're scaling it by a `u64` while using a `U256`. The fraction is guaranteed to have a
        non-zero denominator, ensuring this division won't trap. The quotient will be
        `< u64::MAX` as `rewards_for_network` is and the fraction is `<= 1`.

        This `div_ceil` favors the validators for rewards, not the pools. Because the fraction
        is `<= 1`, even with a `div_ceil`, at most this rounds a number such as `0.999` to `1`
        where `1` is still `<= 1`. This ensures all desired bounds are still respected and the
        result is at not at risk of exceeding the intended rewards for the network.
      */
      let rewards_for_validators = {
        let (quotient, remainder) = (sp_core::U256::from(u128::from(rewards_for_network)) *
          validators_fraction.0)
          .div_mod(validators_fraction.1);
        u64::try_from(quotient)
          .expect("validators' fraction `> 1` or more than a year between blocks") +
          u64::from(u8::from(!remainder.is_zero()))
      };
      // The fraction is guaranteed to be `<= 1`, meaning this subtraction won't underflow.
      let rewards_for_pools = rewards_for_network
        .checked_sub(rewards_for_validators)
        .expect("validators' fraction `> 1`");

      result.push(Amount(rewards_for_validators));

      // Distribute the rewards for the liquidity pools, to the liquidity pools
      for (coin, burnt_fees_for_coin) in network.coins().zip(burnt_fees_by_coin) {
        // `rewards_for_pools` fits within a `u64` and
        // `burnt_fees_for_coin <= burnt_fees_for_network`.
        let rewards_for_pool = Amount(
          (sp_core::U256::from(rewards_for_pools) * sp_core::U256::from(burnt_fees_for_coin))
            .checked_div(sp_core::U256::from(burnt_fees_for_network))
            .map(|rewards_for_pool| u64::try_from(rewards_for_pool).unwrap())
            .unwrap_or(0),
        );
        // Mint directly to the liquidity pool, raising the value of all LP present
        // If the SRI supply somehow hits `u64::MAX`, NOP instead of stalling the chain
        let _ = serai_coins_pallet::Pallet::<T, serai_coins_pallet::CoinsInstance>::mint(
          serai_abi::dex::address(coin),
          Balance { coin: Coin::Serai, amount: rewards_for_pool },
        );
      }
    }

    result
  }

  impl<T: Config> PreInherents for Pallet<T> {
    fn pre_inherents() {
      if EndOfGenesisTimestamp::<T>::get().is_none() {
        // Use if the `Bitcoin` pool was initialized as a flag for if the genesis era is over
        if serai_coins_pallet::Pallet::<T, serai_coins_pallet::LiquidityTokensInstance>::supply(
          ExternalCoin::Bitcoin,
        ) != Amount(0)
        {
          // Because the genesis era ends with
          // [`serai_abi::genesis_liquidity::Call::oraclize_values`], it ended in the prior block
          EndOfGenesisTimestamp::<T>::set(Some(
            TimeOfLastBlock::<T>::get().expect("pools initialized on very first block"),
          ));
        } else {
          // There are no rewards during the genesis era
          return;
        }
      }

      let rewards = if !determine_if_post_economic_security::<T>() {
        let mut rewards = vec![];
        for network in ExternalNetworkId::all() {
          rewards.push(calculate_pre_economic_security_external_set_rewards::<T>(network));
        }
        rewards
      } else {
        effect_post_economic_security_external_network_rewards::<T>()
      };

      for (network, reward) in ExternalNetworkId::all().zip(rewards) {
        /*
          Update the queued rewards for a validator set.

          We save these to the latest decided set, not the current set, as:
          - Both should be active at this time
          - While the current set no longer earns fees, they used to be the latest decided set
            which caused a prior current set to no longer earn fees
          - The current set transition is not regular due to the timeline for the handover.
            Deciding sets SHOULD be regular, barring the inability to decide the next set.
            This means using the latest set provides a more consistent timeline for when a
            validator is earning rewards.
        */
        let Some(latest_decided_session) = T::ValidatorSets::latest_decided_session(network.into())
        else {
          continue;
        };
        ExternalValidatorSetRewards::<T>::mutate(
          ExternalValidatorSet { network, session: latest_decided_session },
          |existing| {
            if let Some(updated) = (*existing) + reward {
              *existing = updated;
            }
          },
        );
      }
    }
  }

  /// The Pallet struct.
  #[pallet::pallet]
  pub struct Pallet<T>(_);

  impl<T: Config> serai_validator_sets_pallet::Emissions for Pallet<T> {
    fn block_reward() -> Amount {
      let Some(end_of_genesis) = EndOfGenesisTimestamp::<T>::get() else {
        // No rewards are emitted during the genesis period
        return Amount(0);
      };

      // If this is post-Economic Security, the block reward is fixed
      // This inlines the literal `SERAI_VALIDATORS_DESIRED_PERCENTAGE`
      if ExternalNetworkId::all().all(T::EconomicSecurity::achieved_economic_security) {
        return Amount(POST_ECONOMIC_SECURITY_REWARD_PER_BLOCK.0 / 5);
      }

      // If this is within the initial period, the block reward is fixed
      let current_time = serai_core_pallet::Pallet::<T>::current_time();
      if u128::from(current_time) < (u128::from(end_of_genesis) + INITIAL_PERIOD.as_millis()) {
        // This inlines the literal `SERAI_VALIDATORS_DESIRED_PERCENTAGE`
        return Amount(INITIAL_PERIOD_REWARD_PER_BLOCK.0 / 5);
      }

      // If this is pre-Economic Security, we reward the Serai validators according to the distance
      // to the desired amount of economic security
      let time_since_genesis =
        current_time.checked_sub(end_of_genesis).expect("Serai timestamps are monotonic");
      let time_until_secure_by =
        SECURE_BY.as_millis().saturating_sub(u128::from(time_since_genesis));
      let blocks_until_secure_by = time_until_secure_by / constants::TARGET_BLOCK_TIME.as_millis();
      // Ensure `blocks_until_secure_by` is non-zero as we are in a block and aren't secure yet
      let blocks_until_secure_by = blocks_until_secure_by.max(1);

      let mut external_stake_required = Some(Amount(0));
      for network in ExternalNetworkId::all() {
        if T::EconomicSecurity::achieved_economic_security(network) {
          continue;
        }

        external_stake_required = external_stake_required.and_then(|external_stake_required| {
          external_stake_required +
            serai_validator_sets_pallet::network_stake_requirement::<T, T::EconomicSecurity>(
              network,
            )
        });
      }

      // If the stake requirement exceeds the possible supply, and is unreachable, NOP
      let Some(external_stake_required) = external_stake_required else { return Amount(0) };
      // We do the same for `u64::MAX` as `u64::MAX` is allowed to be used to symbolize overflow
      if external_stake_required == Amount(u64::MAX) {
        return Amount(0);
      }
      // `SERAI_VALIDATORS_STAKE_DESIRED` with an inlined formula derived from the literal
      // `SERAI_VALIDATORS_DESIRED_PERCENTAGE`
      let serai_validators_stake_desired = external_stake_required.0 / 4;

      let distance = serai_validators_stake_desired
        .saturating_sub(T::ValidatorSets::total_allocated_stake_for_network(NetworkId::Serai).0);
      // This uses a `div_ceil` to _ensure_ the set will be considered secure by this point
      // (barring behavior such as slashes)
      Amount(
        u64::try_from(u128::from(distance).div_ceil(blocks_until_secure_by))
          .expect("numerator fit within a `u64::MAX` so quotient will"),
      )
    }

    fn take_set_reward(set: ExternalValidatorSet) -> Amount {
      let rewards = ExternalValidatorSetRewards::<T>::take(set);
      HistoricalExternalValidatorSetRewards::<T>::insert(set, rewards);
      rewards
    }
  }
}

pub use pallet::{ValidatorSets, Config, Pallet};
#[doc(hidden)]
pub use pallet::*;
