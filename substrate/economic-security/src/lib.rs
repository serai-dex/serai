#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[expect(let_underscore_drop)]
#[frame_support::pallet]
mod pallet {
  use core::{marker::PhantomData, time::Duration};
  extern crate alloc;
  use alloc::vec::Vec;

  use frame_support::pallet_prelude::*;
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
  type ValidatorSets<T> = serai_validator_sets_pallet::Pallet<T>;

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
    + serai_validator_sets_pallet::Config
  {
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
  type PastQuotes<T: Config> = StorageDoubleMap<
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
  type HighestObservedMedian<T: Config> = StorageDoubleMap<
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
  const MEDIAN_LENGTH: Duration = serai_abi::primitives::constants::HOUR.checked_mul(6).unwrap();

  /// The length of the time window to consider the maximum median for.
  ///
  /// This value should be long enough a social response is feasible.
  const MAXIMUM_MEDIAN_LENGTH: Duration = serai_abi::primitives::constants::SESSION_LENGTH;

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
          let stake_requirement = ValidatorSets::<T>::network_stake_requirement(network);
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
            ValidatorSets::<T>::stake_for_current_validator_set(network.into())
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
            PastQuotes::<T>::insert(coin, current_time.lexicographic_encode(), current_quote);
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

              Note `iter_prefix` TECHNICALLY makes no guarantees about the order of the results.
              PRACTICALLY, we used the identity hasher, considered the lexicographic properties of
              the key, and `sp_io::storage` _only_ offers `next_key` for such iteration.
            */
            {
              let stale_median_time =
                Duration::from_millis(current_time).checked_sub(MEDIAN_LENGTH);
              let mut stale_quotes = Vec::with_capacity(2);
              for (time_of_quote, potentially_stale_quote) in
                PastQuotes::<T>::iter_prefix(coin).take(2)
              {
                if Some(Duration::from_millis(u64::lexicographic_decode(time_of_quote))) >
                  stale_median_time
                {
                  break;
                }
                stale_quotes.push((time_of_quote, potentially_stale_quote));
              }
              for (time_of_quote, stale_quote) in stale_quotes {
                PastQuotes::<T>::remove(coin, time_of_quote);
                Median::<T>::pop(coin, stale_quote);
              }
            }

            // Observe the median.
            let observed_median =
              Median::<T>::median(coin).expect("just pushed a value onto the median yet no median");
            ObservedMedians::<T>::insert(
              coin,
              current_time.lexicographic_encode(),
              observed_median,
            );
            HighestObservedMedian::<T>::mutate(
              coin,
              LexicographicReverse::from(&observed_median),
              |value| Some(value.map(|value| value + 1).unwrap_or(1)),
            );
            {
              let stale_median_time =
                Duration::from_millis(current_time).checked_sub(MAXIMUM_MEDIAN_LENGTH);
              let mut stale_medians = Vec::with_capacity(2);
              for (time_of_median, potentially_stale_median) in
                ObservedMedians::<T>::iter_prefix(coin).take(2)
              {
                if Some(Duration::from_millis(u64::lexicographic_decode(time_of_median))) >
                  stale_median_time
                {
                  break;
                }
                stale_medians.push((time_of_median, potentially_stale_median));
              }
              for (time_of_median, stale_median) in stale_medians {
                ObservedMedians::<T>::remove(coin, time_of_median);
                HighestObservedMedian::<T>::mutate(
                  coin,
                  LexicographicReverse::from(&stale_median),
                  |value| {
                    /*
                      The code which inserts this, and removes this, is immediate and obvious.
                      While we could attempt to be graceful, as a panic in `on_initialize` risks
                      stalling the blockchain, this shouldn't panic and it'd be better to stall
                      upon a broken economic security oracle than continue.
                    */
                    let value =
                      value.expect("observed median wasn't present in `HighestObservedMedian`");
                    if value == 1 {
                      None
                    } else {
                      Some(value - 1)
                    }
                  },
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
      let Some(quote_per_unit) = HighestObservedMedian::<T>::iter_prefix(balance.coin)
        .next()
        .map(|(highest_observed_median, _)| highest_observed_median.into())
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
          let stake =
            ValidatorSets::<T>::stake_for_current_validator_set(external_coin.network().into())
              .min(ValidatorSets::<T>::stake_for_latest_decided_validator_set(
                external_coin.network().into(),
              ));
          let stake_requirement =
            ValidatorSets::<T>::coins_stake_requirement(external_coin.network(), Some(*balance));
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

          let stake =
            ValidatorSets::<T>::stake_for_current_validator_set(external_coin.network().into())
              .min(ValidatorSets::<T>::stake_for_latest_decided_validator_set(
                external_coin.network().into(),
              ));
          let sufficient_stake = Some(ValidatorSets::<T>::liquidity_tokens_stake_requirement(
            external_coin.network(),
          )) <= stake;
          ExternalNetworkId::all().all(Pallet::<T>::achieved_economic_security) && sufficient_stake
        }
      }
    }
  }
}

pub use pallet::{Config, Pallet, CoinsInstanceAllowMint, LiquidityTokensInstanceAllowMint};
#[doc(hidden)]
pub use pallet::*;
