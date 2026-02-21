#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

extern crate alloc;

#[expect(let_underscore_drop)]
#[frame_support::pallet]
mod pallet {
  use core::time::Duration;

  use frame_support::{pallet_prelude::*, traits::PreInherents};

  use serai_abi::{
    primitives::{
      constants,
      network_id::*,
      coin::{ExternalCoin, Coin},
      balance::{Amount, Balance},
      validator_sets::*,
    },
    economic_security::EconomicSecurity,
    TransactionContext as _,
  };

  const DAYS_365: Duration = constants::DAY.checked_mul(365).unwrap();

  const INITIAL_PERIOD: Duration = constants::DAY.checked_mul(30).unwrap();
  const INITIAL_PERIOD_REWARDS: Amount = Amount(100_000 * 10u64.pow(Coin::Serai.decimals()));
  #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
  const INITIAL_PERIOD_REWARD_PER_BLOCK: Amount = Amount(
    (((INITIAL_PERIOD_REWARDS.0 as u128) * constants::TARGET_BLOCK_TIME.as_millis()) /
      INITIAL_PERIOD.as_millis()) as u64,
  );
  const SECURE_BY: Duration = DAYS_365;

  const POST_ECONOMIC_SECURITY_REWARDS_PER_365_DAYS: Amount =
    Amount(20_000_000 * 10u64.pow(Coin::Serai.decimals()));
  #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
  const BLOCKS_PER_365_DAYS: u64 =
    DAYS_365.as_millis().checked_div(constants::TARGET_BLOCK_TIME.as_millis()).unwrap() as u64;
  const POST_ECONOMIC_SECURITY_REWARD_PER_BLOCK: Amount =
    Amount(POST_ECONOMIC_SECURITY_REWARDS_PER_365_DAYS.0 / BLOCKS_PER_365_DAYS);

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

  /// The time from the first block after the pools were initialized.
  #[pallet::storage]
  type PostGenesisTimestamp<T: Config> = StorageValue<_, u64, OptionQuery>;
  /// The first sessions for external networks after achieving Economic Security.
  ///
  /// If Economic Security has yet to be reached, this will be the latest decided sessions.
  ///
  /// We use this to track the first sessions to exist post-Economic Security. After Economic
  /// Security is reached, we no longer need this so we stop updating it. That leaves its values in
  /// the state as described.
  #[pallet::storage]
  type FirstSessionsAfterEconomicSecurity<T: Config> =
    StorageMap<_, Identity, ExternalNetworkId, Session, OptionQuery>;
  /// If a prior validator set for every network has achieved economic set.
  #[pallet::storage]
  type PriorAchievedEconomicSecurity<T: Config> = StorageValue<_, (), OptionQuery>;
  /// The time of the last block.
  ///
  /// This is set to the time of the current block within [`PreInherents::pre_inherents`], not at
  /// the end of the current block. It is only accurate as described before then.
  #[pallet::storage]
  type TimeOfLastBlock<T: Config> = StorageValue<_, u64, OptionQuery>;
  /// Rewards for an external validator set.
  #[pallet::storage]
  type ExternalValidatorSetRewards<T: Config> =
    StorageMap<_, Identity, ExternalValidatorSet, Amount, ValueQuery>;

  /// The fraction of rewards which should go to an external network's validators, per the
  /// post-Economic Security policy.
  ///
  /// This is programmed to never panic. The fraction will be within the range `0 ..= 1`. The
  /// numerator and denominator will fit within `u192`, enabling further scaling by a `u64`, and
  /// the denominator will be non-zero, ensuring it can be divided by.
  fn post_economic_security_external_network_validator_rewards_fraction(
    used_capacity: Amount,
    capacity_of_network: Amount,
  ) -> (sp_core::U256, sp_core::U256) {
    use sp_core::U256;

    /*
      `DESIRED_UNUSED_CAPACITY = 0.1`

      This fraction has to be any non-zero accurate representation where it should be irreducible
      to minimize the risks of overflows.
    */
    const DESIRED_UNUSED_CAPACITY: (u8, u8) = (1, 10);
    /*
      `DESIRED_DISTRIBUTION = 1 - DESIRED_UNUSED_CAPACITY`

      This is `(1 / 1) - DESIRED_UNUSED_CAPACITY`, with `1 / 1` represented as
      `DESIRED_UNUSED_CAPACITY_DENOM / DESIRED_UNUSED_CAPACITY_DENOM` to allow us to
      perform the subtraction.
    */
    const DESIRED_DISTRIBUTION: (u8, u8) =
      (DESIRED_UNUSED_CAPACITY.1 - DESIRED_UNUSED_CAPACITY.0, DESIRED_UNUSED_CAPACITY.1);

    // There cannot be more capacity used than in existence, even if we _require_ more than exists
    let used_capacity = used_capacity.min(capacity_of_network);

    // If this network lacks capacity, state it should receive `1/1` of the rewards
    if capacity_of_network == Amount(0) {
      return (sp_core::U256::one(), sp_core::U256::one());
    } else if used_capacity == Amount(0) {
      // If this network has capacity but none is used, say the validators should get `0/1`
      // (so the pools receive `1/1`)
      return (sp_core::U256::zero(), sp_core::U256::one());
    }

    let current_distribution = (used_capacity.0, capacity_of_network.0);

    // These values are bounded `0 ..= u8::MAX`
    let ratio_term_for_validators = DESIRED_UNUSED_CAPACITY;

    // `((1 - CURRENT_DISTRIBUTION) * DESIRED_DISTRIBUTION) / CURRENT_DISTRIBUTION`
    let ratio_term_for_pools = {
      let one_minus_current_distribution_times_desired_distribution = {
        // This won't trap as `current_distribution <= 1`
        // These values are bounded `0 ..= u64::MAX`
        let one_minus_current_distribution =
          (current_distribution.1 - current_distribution.0, current_distribution.1);
        // These values are bounded `0 ..= u72::MAX`
        (
          u128::from(one_minus_current_distribution.0) *
            u128::from(u16::from(DESIRED_DISTRIBUTION.0)),
          u128::from(one_minus_current_distribution.1) *
            u128::from(u16::from(DESIRED_DISTRIBUTION.1)),
        )
      };
      // These values are bounded `0 ..= u136::MAX`
      (
        U256::from(one_minus_current_distribution_times_desired_distribution.0) *
          U256::from(u128::from(current_distribution.1)),
        U256::from(one_minus_current_distribution_times_desired_distribution.1) *
          U256::from(u128::from(current_distribution.0)),
      )
    };

    // `ratio_term_for_validators / ratio_term_for_pools`
    // These values are bounded `0 ..= u144::MAX`
    let ratio = (
      U256::from(u16::from(ratio_term_for_validators.0)) * ratio_term_for_pools.1,
      U256::from(u16::from(ratio_term_for_validators.1)) * ratio_term_for_pools.0,
    );

    // Now that we have the ratio, we convert to the validators' fraction, as useful by consumers.
    // These values are bounded `0 ..= u145::MAX` which is a subset of `0 ..= u192::MAX`, the
    // documented bound for the returned values from this function
    (ratio.0, ratio.0 + ratio.1)
  }

  impl<T: Config> PreInherents for Pallet<T> {
    fn pre_inherents() {
      let current_time = serai_core_pallet::Pallet::<T>::current_time();

      // This uses if the `Bitcoin` liquidity pool was initialized as a flag for if genesis is over
      if PostGenesisTimestamp::<T>::get().is_none() &&
        (serai_coins_pallet::Pallet::<T, serai_coins_pallet::LiquidityTokensInstance>::supply(
          ExternalCoin::Bitcoin,
        ) != Amount(0))
      {
        PostGenesisTimestamp::<T>::set(Some(current_time));
      }

      /*
        If a new external validator set has been declared, decide if it's the first external
        validator set declared such that for all external networks, a prior validator set had
        achieved economic security. If so, we transition to the post-Economic Security rewards
        specification for all current and future validator sets.
      */
      if PriorAchievedEconomicSecurity::<T>::get().is_none() {
        let mut new_external_set = false;
        for network in ExternalNetworkId::all() {
          let latest_decided_session = T::ValidatorSets::latest_decided_session(network.into());
          if latest_decided_session > FirstSessionsAfterEconomicSecurity::<T>::get(network) {
            new_external_set = true;
            FirstSessionsAfterEconomicSecurity::<T>::set(network, latest_decided_session);
          }
        }
        if new_external_set &&
          ExternalNetworkId::all().all(T::EconomicSecurity::achieved_economic_security)
        {
          PriorAchievedEconomicSecurity::<T>::set(Some(()));
          for coin in ExternalCoin::all() {
            // Drop the tally of all fees burnt pre-Economic Security
            let _ = serai_dex_pallet::Pallet::<T>::take_burnt_fees(coin);
          }
        }
      } else {
        // If we're handling sets which are post-Economic Security, calculate the post-ES rewards
        let mut total_burnt_fees = 0u128;
        let mut burnt_fees_by_coin = alloc::collections::BTreeMap::new();
        let mut burnt_fees_by_network = alloc::collections::BTreeMap::new();
        for network in ExternalNetworkId::all() {
          for coin in network.coins() {
            let burnt_fees_for_coin: u128 = serai_dex_pallet::Pallet::<T>::take_burnt_fees(coin);
            // This won't overflow as individual fee burns are `u64` but this accumulator is a
            // `u128`, requiring `2**64` fee burns to occur in a single block to overflow
            total_burnt_fees += burnt_fees_for_coin;
            burnt_fees_by_coin.insert(coin, burnt_fees_for_coin);
            let burnt_fees_for_network =
              burnt_fees_by_network.get(&network).copied().unwrap_or(0) + burnt_fees_for_coin;
            burnt_fees_by_network.insert(network, burnt_fees_for_network);
          }
        }

        let time_of_last_block = TimeOfLastBlock::<T>::get()
          .expect("prior achieved economic security on the very first block");
        let time_to_consider_rewards_for =
          current_time.checked_sub(time_of_last_block).expect("Serai timestamps are monotonic");
        /*
          This will itself fit in a `u64` if the time between two blocks is less than a year,
          which can be assumed without issue. Even then, it'd have to be
          `u64::MAX / POST_ECONOMIC_SECURITY_REWARDS_PER_365_DAYS` years, in which case the
          network has much larger problems.
        */
        let rewards = u64::try_from(
          (u128::from(POST_ECONOMIC_SECURITY_REWARDS_PER_365_DAYS.0) *
            u128::from(time_to_consider_rewards_for)) /
            DAYS_365.as_millis(),
        )
        .expect("time between blocks exceeded one year");

        for (network, burnt_fees_for_network) in burnt_fees_by_network {
          /*
            Note this methodology actually enables a form of arbitrage such that if the cost to
            burn fees within a pool is sufficiently low, it can be worth more by the increased
            amount of rewards which will be distributed to the pool. This is actually beneficial
            for Serai as if Serai is distributing too much SRI in rewards, 'adversaries' have
            incentive to _perform burns themselves for their profit_, reducing the overall SRI
            supply compared to if they did nothing.

            While it is arguably hostile to other pools, all users within a pool are still treated
            equally and any pool can have an entity perform this arbitrage for it, so it's as level
            a playing field as Serai inherently is.
          */
          let rewards_for_network = (sp_core::U256::from(u128::from(rewards)) *
            sp_core::U256::from(burnt_fees_for_network))
          .checked_div(sp_core::U256::from(total_burnt_fees))
          .map(|amount| {
            u64::try_from(amount).expect("`burnt_fees_for_network > total_burnt_fees`?")
          })
          .unwrap_or(0);

          let validators_fraction = {
            // Note this may be `u64::MAX` if an overflow occurred. In that case, we still use it
            // as-is as because the methodology within
            // `post_economic_security_external_network_validator_rewards_fraction` will bound it
            // to be at most `capacity_of_network` (used capacity is `<=` actual capacity).
            let used_capacity = serai_validator_sets_pallet::network_stake_requirement::<
              T,
              T::EconomicSecurity,
            >(network);
            /*
              We use the capacity of the latest decided set as:
              - It will take over, so its economic security we primarily care about.
              - The latest decided set will receive these fees, for reasons described below.
            */
            let capacity_of_network =
              T::ValidatorSets::stake_for_latest_decided_validator_set(network.into())
                .unwrap_or(Amount(0));
            post_economic_security_external_network_validator_rewards_fraction(
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

          /*
            Update the queued rewards for a validator set.

            We save these to the latest decided set, not the current set, as:
            - Both should be active at this time
            - While the current set no longer earns fees, they used to be the latest decided set
              which caused a prior current set to no longer earn fees
            - The current set transition is not regular due to the timeline for the handover.
              Deciding sets SHOULD be regular, barring the inability to decide the next set
          */
          ExternalValidatorSetRewards::<T>::mutate(
            ExternalValidatorSet {
              network,
              session: T::ValidatorSets::latest_decided_session(network.into())
                .expect("post-economic security but network without session"),
            },
            |existing| {
              *existing = ((*existing) + Amount(rewards_for_validators))
                .expect("lifetime of a session exceeded one year");
            },
          );

          // Distribute the rewards for the liquidity pools, to the liquidity pools
          for coin in network.coins() {
            let burnt_fees_for_coin = burnt_fees_by_coin[&coin];
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
      }

      TimeOfLastBlock::<T>::set(Some(current_time));
    }
  }

  /// The Pallet struct.
  #[pallet::pallet]
  pub struct Pallet<T>(_);

  impl<T: Config> serai_validator_sets_pallet::Emissions for Pallet<T> {
    fn block_reward() -> Amount {
      let Some(end_of_genesis) = PostGenesisTimestamp::<T>::get() else {
        // No rewards are emitted during the genesis period
        return Amount(0);
      };

      // If this is within the initial period, the block reward is fixed
      let current_time = serai_core_pallet::Pallet::<T>::current_time();
      if (u128::from(end_of_genesis) + INITIAL_PERIOD.as_millis()) < u128::from(current_time) {
        return INITIAL_PERIOD_REWARD_PER_BLOCK;
      }

      // If this is pre-Economic Security, we reward the Serai validators according to the distance
      // to the desired amount of economic security
      if !ExternalNetworkId::all().all(T::EconomicSecurity::achieved_economic_security) {
        let time_since_genesis =
          current_time.checked_sub(end_of_genesis).expect("Serai timestamps are monotonic");
        let time_until_secure_by =
          SECURE_BY.as_millis().saturating_sub(u128::from(time_since_genesis));
        let blocks_until_secure_by =
          time_until_secure_by / constants::TARGET_BLOCK_TIME.as_millis();
        // Ensure `blocks_until_secure_by` is non-zero as we are in a block and aren't secure yet
        let blocks_until_secure_by = blocks_until_secure_by.max(1);

        let mut external_stake = Amount(0);
        let mut external_stake_required = Some(Amount(0));
        for network in ExternalNetworkId::all() {
          if T::EconomicSecurity::achieved_economic_security(network) {
            continue;
          }

          external_stake = (external_stake +
            T::ValidatorSets::total_allocated_stake_for_network(network.into()))
          .expect("stake exceed SRI supply (bounded to `u64::MAX`)");
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
        return Amount(
          u64::try_from(u128::from(distance).div_ceil(blocks_until_secure_by))
            .expect("numerator fit within a `u64::MAX` so quotient will"),
        );
      }

      // If this is post-Economic Security, the reward is fixed
      // This inlines the literal `SERAI_VALIDATORS_DESIRED_PERCENTAGE`
      Amount(POST_ECONOMIC_SECURITY_REWARD_PER_BLOCK.0 / 5)
    }

    fn take_set_reward(set: ExternalValidatorSet) -> Amount {
      let Some(end_of_genesis) = PostGenesisTimestamp::<T>::get() else {
        // No rewards are emitted during the genesis period
        return Amount(0);
      };

      if !ExternalNetworkId::all().all(T::EconomicSecurity::achieved_economic_security) {
        if T::EconomicSecurity::achieved_economic_security(set.network) {
          return Amount(0);
        }

        let current_time = serai_core_pallet::Pallet::<T>::current_time();
        let time_since_genesis =
          current_time.checked_sub(end_of_genesis).expect("Serai timestamps are monotonic");
        let time_until_secure_by =
          SECURE_BY.as_millis().saturating_sub(u128::from(time_since_genesis));
        let sessions_until_secure_by = time_until_secure_by / constants::SESSION_LENGTH.as_millis();
        let sessions_until_secure_by = sessions_until_secure_by.max(1);

        let stake = T::ValidatorSets::total_allocated_stake_for_network(set.network.into());
        let stake_required = serai_validator_sets_pallet::network_stake_requirement::<
          T,
          T::EconomicSecurity,
        >(set.network);
        // If the amount of stake required has overflowed and is unreachable, NOP
        if stake_required == Amount(u64::MAX) {
          return Amount(0);
        }

        let distance = stake_required.0.saturating_sub(stake.0);
        return Amount(
          u64::try_from(u128::from(distance).div_ceil(sessions_until_secure_by))
            .expect("numerator fit within a `u64::MAX` so quotient will"),
        );
      }

      ExternalValidatorSetRewards::<T>::take(set)
    }
  }
}

pub use pallet::{ValidatorSets, Config, Pallet};
#[doc(hidden)]
pub use pallet::*;
