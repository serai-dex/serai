#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(test)]
mod tests;

#[expect(let_underscore_drop)]
#[frame_support::pallet]
mod pallet {
  use core::{marker::PhantomData, num::NonZero, time::Duration};
  extern crate alloc;
  use alloc::vec::Vec;

  use scale::FullCodec;
  use frame_support::{pallet_prelude::*, IterableStorageDoubleMap};
  use frame_system::pallet_prelude::*;

  use substrate_median::{LexicographicEncoding, LexicographicReverse, Policy, Median as _};

  use serai_abi::{
    primitives::prelude::*, economic_security::EconomicSecurity, TransactionContext as _,
  };

  use serai_core_pallet::Pallet as Core;
  #[expect(unused)]
  type Coins<T> = serai_coins_pallet::Pallet<T, serai_coins_pallet::CoinsInstance>;
  type LiquidityTokens<T> =
    serai_coins_pallet::Pallet<T, serai_coins_pallet::LiquidityTokensInstance>;
  type Dex<T> = serai_dex_pallet::Pallet<T>;

  /// Methods from [`serai_validator_sets_pallet::Pallet`] which [`Pallet`] requires.
  ///
  /// This is behind a `trait` to allow shimming it when testing. For the exact description, and
  /// bounds, of these methods, please refer to [`serai_validator_sets_pallet::Pallet`].
  pub trait ValidatorSets {
    /// The stake for the current validator set for a network.
    fn stake_for_current_validator_set(network: NetworkId) -> Option<Amount>;
    /// The stake for the latest decided validator set for a network.
    fn stake_for_latest_decided_validator_set(network: NetworkId) -> Option<Amount>;
    /// The required amount of SRI which must be allocated as stake for a network to be considered
    /// economically secure regarding the total amount of coins.
    fn coins_stake_requirement(
      network: ExternalNetworkId,
      proposed_additional_balance: Option<Balance>,
    ) -> Amount;
    /// The required amount of SRI which must be allocated as stake for a network to be considered
    /// economically secure regarding the coins in the liquidity pool.
    fn liquidity_tokens_stake_requirement(network: ExternalNetworkId) -> Amount;
    /// The required amount of SRI which must be allocated as stake for a network to be considered
    /// economically secure.
    fn network_stake_requirement(network: ExternalNetworkId) -> Amount;
  }

  impl<T: Config + serai_validator_sets_pallet::Config<EconomicSecurity = Pallet<T>>> ValidatorSets
    for serai_validator_sets_pallet::Pallet<T>
  {
    fn stake_for_current_validator_set(network: NetworkId) -> Option<Amount> {
      serai_validator_sets_pallet::Pallet::<T>::stake_for_current_validator_set(network)
    }
    fn stake_for_latest_decided_validator_set(network: NetworkId) -> Option<Amount> {
      serai_validator_sets_pallet::Pallet::<T>::stake_for_latest_decided_validator_set(network)
    }
    fn coins_stake_requirement(
      network: ExternalNetworkId,
      proposed_additional_balance: Option<Balance>,
    ) -> Amount {
      serai_validator_sets_pallet::Pallet::<T>::coins_stake_requirement(
        network,
        proposed_additional_balance,
      )
    }
    fn liquidity_tokens_stake_requirement(network: ExternalNetworkId) -> Amount {
      serai_validator_sets_pallet::Pallet::<T>::liquidity_tokens_stake_requirement(network)
    }
    fn network_stake_requirement(network: ExternalNetworkId) -> Amount {
      serai_validator_sets_pallet::Pallet::<T>::network_stake_requirement(network)
    }
  }

  /// The configuration of this pallet.
  #[pallet::config]
  pub trait Config:
    frame_system::Config
    + serai_core_pallet::Config
    + serai_coins_pallet::Config<
      serai_coins_pallet::CoinsInstance,
      AllowMint = CoinsInstanceAllowMint<Self>,
    > + serai_coins_pallet::Config<
      serai_coins_pallet::LiquidityTokensInstance,
      AllowMint = LiquidityTokensInstanceAllowMint<Self>,
    > + serai_dex_pallet::Config
  {
    /// The validator sets pallet.
    type ValidatorSets: ValidatorSets;
  }

  /// The Pallet struct.
  #[pallet::pallet]
  pub struct Pallet<T>(_);

  /// If any validator set for an external network has ever achieved economic security.
  #[pallet::storage]
  type AchievedEconomicSecurity<T: Config> =
    StorageMap<_, Identity, ExternalNetworkId, (), OptionQuery>;

  /// Past quotes pushed onto the median, keyed by the time they were pushed.
  ///
  /// We use the keys' lexicographic properties to iterate from oldest to latest.
  #[pallet::storage]
  pub(crate) type PastQuotes<T: Config> = StorageDoubleMap<
    _,
    Identity,
    ExternalCoin,
    Identity,
    <u64 as LexicographicEncoding>::Encoding,
    u128,
    OptionQuery,
  >;

  // All of the storage values to satisfy `substrate_median`.
  #[pallet::storage]
  type MedianLength<T: Config> = StorageMap<_, Identity, ExternalCoin, u64, ValueQuery>;
  #[pallet::storage]
  type MedianStore<T: Config> = StorageDoubleMap<
    _,
    Identity,
    ExternalCoin,
    Identity,
    <u128 as LexicographicEncoding>::Encoding,
    u64,
    ValueQuery,
  >;
  #[pallet::storage]
  type MedianReverseStore<T: Config> = StorageDoubleMap<
    _,
    Identity,
    ExternalCoin,
    Identity,
    LexicographicReverse<u128>,
    (),
    ValueQuery,
  >;
  #[pallet::storage]
  type MedianPosition<T: Config> = StorageMap<_, Identity, ExternalCoin, u64, OptionQuery>;
  #[pallet::storage]
  type MedianMedian<T: Config> = StorageMap<_, Identity, ExternalCoin, u128, OptionQuery>;
  struct Median<T: Config>(PhantomData<T>);
  impl<T: Config> substrate_median::MedianStore<ExternalCoin, u128> for Median<T> {
    const POLICY: Policy = Policy::Average;
    type Length = MedianLength<T>;
    type Store = MedianStore<T>;
    type ReverseStore = MedianReverseStore<T>;
    type Position = MedianPosition<T>;
    type Median = MedianMedian<T>;
  }

  /// A map to track the observed medians.
  ///
  /// This has the same methodology as `PastQuotes` where medians are keyed by the time they were
  /// observed, allowing us to iterate over the observed medians from oldest to newest.
  #[pallet::storage]
  type ObservedMedians<T: Config> = StorageDoubleMap<
    _,
    Identity,
    ExternalCoin,
    Identity,
    <u64 as LexicographicEncoding>::Encoding,
    u128,
    OptionQuery,
  >;
  /// A map to determine the highest observed median.
  ///
  /// The first key within this map will be the highest median. The value will be the amount of
  /// presences.
  #[pallet::storage]
  pub(crate) type HighestObservedMedian<T: Config> = StorageDoubleMap<
    _,
    Identity,
    ExternalCoin,
    Identity,
    LexicographicReverse<u128>,
    u64,
    OptionQuery,
  >;

  /// The length of the time window to consider within the median.
  ///
  /// This value should be long enough manipulation is infeasible but also still short enough to
  /// be responsive. With a window of 6 hours, any quote sustained for >3 hours will become the
  /// median's value. Note adding external coins to Serai may take over an hour due to the latency
  /// of external networks.
  pub(crate) const MEDIAN_LENGTH: Duration =
    serai_abi::primitives::constants::HOUR.checked_mul(6).unwrap();

  /// The length of the time window to consider the maximum median for.
  ///
  /// This value should be long enough a social response is feasible.
  pub(crate) const MAXIMUM_MEDIAN_LENGTH: Duration =
    serai_abi::primitives::constants::SESSION_LENGTH;

  /// Insert a value into a storage map by its time of insertion.
  ///
  /// This allows using the following `find_historical_values` function _if_ the hasher for the
  /// second key is `Identity`.
  pub(crate) fn insert_value_by_time<
    K: FullCodec,
    V: FullCodec,
    T: IterableStorageDoubleMap<K, <u64 as LexicographicEncoding>::Encoding, V, Query = Option<V>>,
  >(
    key: K,
    time: u64,
    value: V,
  ) {
    T::insert(key, time.lexicographic_encode(), value);
  }

  /// Find historical values with a storage map.
  ///
  /// This _requires_ the hasher for the second key be `Identity`.
  ///
  /// The result is the list of `Time, V` pairs of found historical values (values whose times of
  /// insertion are less than the current time minus the age limit). The result is explicitly eager
  /// such that even if iterating and mutating storage incurs undefined behavior, a call to this
  /// function will perform _the entire iteration at time of call_. This allows immediately
  /// iterating over the result to perform the presumably desired removals. Unfortunately, this
  /// prevents returning a non-allocating `impl Iterator`.
  ///
  /// This will only iterate up to `bound` and return a result of length less than or equal to the
  /// bound.
  pub(crate) fn find_historical_values<
    K: FullCodec,
    V: FullCodec,
    T: IterableStorageDoubleMap<K, <u64 as LexicographicEncoding>::Encoding, V, Query = Option<V>>,
  >(
    key: K,
    current_time_in_millis: u64,
    age_limit: Duration,
    bound: usize,
  ) -> Vec<(<u64 as LexicographicEncoding>::Encoding, V)> {
    let stale_time = Duration::from_millis(current_time_in_millis).checked_sub(age_limit);

    /*
      Note `iter_prefix` TECHNICALLY makes no guarantees about the order of the results.
      PRACTICALLY, we used the identity hasher for all maps this is called with, considered the
      lexicographic properties of the key, and `sp_io::storage` _only_ offers `next_key` for such
      iteration.
    */
    let mut result = Vec::with_capacity(bound);
    for (time_of_insertion, potentially_stale_value) in T::iter_prefix(key).take(bound) {
      if Some(Duration::from_millis(u64::lexicographic_decode(time_of_insertion))) > stale_time {
        break;
      }
      result.push((time_of_insertion, potentially_stale_value));
    }
    result
  }

  /// Insert a value into a storage map used to calculate the highest value within a multiset.
  ///
  /// This _requires_ the hasher for the second key be `Identity`.
  ///
  /// This will _increment_ the amount of presences.
  pub(crate) fn insert_possible_highest_value<
    K: FullCodec,
    V: LexicographicEncoding,
    T: IterableStorageDoubleMap<K, LexicographicReverse<V>, u64, Query = Option<u64>>,
  >(
    key: &K,
    value: &V,
  ) {
    T::mutate(key, LexicographicReverse::from(value), |presences| {
      // Increment by `1` if the value exists, otherwise set to `1`
      *presences = Some(presences.map(|presences| presences + 1).unwrap_or(1));
    });
  }

  /// Remove a value from a storage map used to calculate the highest value within a multiset.
  ///
  /// This _requires_ the hasher for the second key be `Identity`.
  ///
  /// This will _decrement_ the amount of presences, panicking if not present at all.
  ///
  /// In context, this private function is called within `on_initialize`, meaning it panicking
  /// could stall the blockchain. The use of the function is immedate and direct to verify however,
  /// and removing a value which is not present symbolizes a broken economic security oracle. In
  /// that case, it's better to stall than continue operation.
  pub(crate) fn remove_possible_highest_value<
    K: FullCodec,
    V: LexicographicEncoding,
    T: IterableStorageDoubleMap<K, LexicographicReverse<V>, u64, Query = Option<u64>>,
  >(
    key: K,
    value: &V,
  ) {
    T::mutate(key, LexicographicReverse::from(value), |presences| {
      let presences_value =
        presences.expect("possible highest value wasn't present in storage map");
      // Decrement the value, yielding `None` if now `0`
      *presences = NonZero::new(presences_value - 1).map(NonZero::get);
    });
  }

  /// Fetch the highest value within a multiset.
  ///
  /// This _requires_ the hasher for the second key be `Identity`.
  pub(crate) fn highest_value<
    K: FullCodec,
    V: LexicographicEncoding,
    T: IterableStorageDoubleMap<K, LexicographicReverse<V>, u64, Query = Option<u64>>,
  >(
    key: K,
  ) -> Option<V> {
    /*
      The first key, with the lowest lexicographic order, will be the highest value due to the
      usage of `LexicographicReverse`.

      This has the same comment on the use of `iter_prefix` as above, that it is _technically_
      undefined.
    */
    T::iter_prefix(key).next().map(|(value, _presences)| value.into())
  }

  #[pallet::hooks] // serai-core-pallet: allow
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(_block_number: BlockNumberFor<T>) -> Weight {
      /*
        Check if any network achieved economic security for the first time.

        This is linear in the amount of external networks, though calculating the stake
        requirements is linear in the amount of coins for the network, making this linear in the
        amount of external coins.
      */
      for network in ExternalNetworkId::all() {
        if AchievedEconomicSecurity::<T>::get(network).is_none() {
          let stake_requirement = T::ValidatorSets::network_stake_requirement(network);
          // If no requirement has been set yet, don't test if it has been met
          if stake_requirement == Amount(0) {
            continue;
          }

          /*
            Generally, we check the current and latest decided set. Either way, here, we will be
            rotating to the latest decided set and if it will be economically insecure, it will be.
            Because the rotation will happen regardless, we'd rather track if _ever_ reached, as
            documented, in order to begin the new rule set and more directly enforce the condition.
          */
          if Some(stake_requirement) <=
            T::ValidatorSets::stake_for_current_validator_set(network.into())
          {
            AchievedEconomicSecurity::<T>::insert(network, ());
          }
        }
      }

      /*
        Update the medians.

        We can assume this is a constant complexity of length linear to the amount of external
        networks/coins, potentially with a factor `<= 3` depending on the block production
        schedule.
      */
      {
        let current_time = Core::<T>::current_time();
        for coin in ExternalCoin::all() {
          if let Some(current_quote) = Dex::<T>::sri_quote(coin) {
            /*
              Serai's header explicitly guarantees the time will not just never decrement but also
              explicitly increase between blocks, making this insertion not at risk of overwriting
              an existing value.
            */
            insert_value_by_time::<_, _, PastQuotes<T>>(coin, current_time, current_quote);
            Median::<T>::push(coin, current_quote);

            /*
              Check if we should remove past quotes which are now outside of the median's window.

              Because blocks do not follow a strict time table, there may be _multiple_ quotes
              eligible for removal. We explicitly remove up to two expired quotes as that will
              _always_ decrease the length of the median (due to only inserting a single value),
              even if there is a back log.

              Alternatively, with full support for Substrate's weights, we could iterate
              arbitrarily here and remove all historical values until the block itself runs out of
              capacity (potentially leaving no room for transactions).
            */
            {
              let historical_quotes =
                find_historical_values::<_, _, PastQuotes<T>>(coin, current_time, MEDIAN_LENGTH, 2);
              for (time_of_quote, stale_quote) in historical_quotes {
                PastQuotes::<T>::remove(coin, time_of_quote);
                Median::<T>::pop(coin, stale_quote);
              }
            }

            /*
              Observe the median.

              This may be spiked if the median window is incredibly small. That should only happen
              on genesis, when this isn't a concern due to the inability for an adversary to spike
              the amount of SRI in the pool, or if an incredible amount of slots are missed, in
              which case the activation of the protections this could cause, while a DoS, may be
              legitimately desirable.
            */
            {
              let observed_median = Median::<T>::median(coin)
                .expect("just pushed a value onto the median yet no median");
              insert_value_by_time::<_, _, ObservedMedians<T>>(coin, current_time, observed_median);
              insert_possible_highest_value::<_, _, HighestObservedMedian<T>>(
                &coin,
                &observed_median,
              );
            }
            {
              let historical_medians = find_historical_values::<_, _, ObservedMedians<T>>(
                coin,
                current_time,
                MAXIMUM_MEDIAN_LENGTH,
                2,
              );
              for (time_of_median, stale_median) in historical_medians {
                ObservedMedians::<T>::remove(coin, time_of_median);
                remove_possible_highest_value::<_, _, HighestObservedMedian<T>>(
                  coin,
                  &stale_median,
                );
              }
            }
          }
        }
      }

      Weight::zero()
    }
  }

  impl<T: Config> EconomicSecurity for Pallet<T> {
    fn achieved_economic_security(network: ExternalNetworkId) -> bool {
      AchievedEconomicSecurity::<T>::get(network).is_some()
    }

    fn sri_value(balance: ExternalBalance) -> Amount {
      // This falls back to the live quote for the edge case this is called within the same block
      // the pools are initialized during
      let Some(quote_per_unit) = highest_value::<_, _, HighestObservedMedian<T>>(balance.coin)
        .or_else(|| Dex::<T>::sri_quote(balance.coin))
      else {
        // If there's no quote available, there is no SRI valuation for these coins
        return Amount(0);
      };
      let quote_for_balance = (u128::from(balance.amount.0) * quote_per_unit) /
        u128::from(10u64.pow(balance.coin.decimals()));
      Amount(u64::try_from(quote_for_balance).unwrap_or(u64::MAX))
    }
  }

  /// The `AllowMint` for `serai_coins_pallet::Pallet<T, CoinsInstance>`.
  ///
  /// This will only allow a mint of coins if _all_ coins are valued at less than the stated amount
  /// of stake required _before applying the buffer_, unless it's the pre-Economic Security era.
  pub struct CoinsInstanceAllowMint<T: Config>(PhantomData<T>);
  impl<T: Config> serai_coins_pallet::AllowMint for CoinsInstanceAllowMint<T> {
    fn is_allowed(balance: &Balance) -> bool {
      match balance.coin.network() {
        NetworkId::Serai => {}
        NetworkId::External(network) => {
          // Networks which have yet to reach economic security are not subject to its bounds
          if !Pallet::<T>::achieved_economic_security(network) {
            return true;
          }
        }
      }

      match balance.coin {
        Coin::Serai => true,
        Coin::External(external_coin) => {
          let stake = T::ValidatorSets::stake_for_current_validator_set(
            external_coin.network().into(),
          )
          .min(T::ValidatorSets::stake_for_latest_decided_validator_set(
            external_coin.network().into(),
          ));
          let stake_requirement =
            T::ValidatorSets::coins_stake_requirement(external_coin.network(), Some(*balance));
          Some(stake_requirement) <= stake
        }
      }
    }
  }
  /// The `AllowMint` for `serai_coins_pallet::Pallet<T, LiquidityTokensInstance>`.
  ///
  /// This will only allow a mint of liquidity tokens if the coins in the pool are valued at
  /// less than the stated amount of stake required, including the buffer.
  ///
  /// This `struct`'s `AllowMint` implementation IGNORES `balance.amount`. It MUST be run after the
  /// underlying coins have already been transferred as relevant.
  ///
  /// This has undefined behavor if asked to mint `Coin::Serai` which is not valid for a liquidity
  /// token.
  pub struct LiquidityTokensInstanceAllowMint<T: Config>(PhantomData<T>);
  impl<T: Config> serai_coins_pallet::AllowMint for LiquidityTokensInstanceAllowMint<T> {
    fn is_allowed(balance: &Balance) -> bool {
      match balance.coin {
        Coin::Serai => unreachable!("there is no SRI liquidity token"),
        Coin::External(external_coin) => {
          // If this is the genesis liquidity being added, allow the mint unconditionally
          if LiquidityTokens::<T>::supply(balance.coin) == Amount(0) {
            return true;
          }

          let stake = T::ValidatorSets::stake_for_current_validator_set(
            external_coin.network().into(),
          )
          .min(T::ValidatorSets::stake_for_latest_decided_validator_set(
            external_coin.network().into(),
          ));
          let sufficient_stake =
            Some(T::ValidatorSets::liquidity_tokens_stake_requirement(external_coin.network())) <=
              stake;
          ExternalNetworkId::all().all(Pallet::<T>::achieved_economic_security) && sufficient_stake
        }
      }
    }
  }
}

pub use pallet::{Config, Pallet, CoinsInstanceAllowMint, LiquidityTokensInstanceAllowMint};
#[doc(hidden)]
pub use pallet::*;
