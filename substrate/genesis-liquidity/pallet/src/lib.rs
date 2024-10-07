#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[allow(
  unreachable_patterns,
  clippy::cast_possible_truncation,
  clippy::no_effect_underscore_binding,
  clippy::empty_docs
)]
#[frame_support::pallet]
pub mod pallet {
  use super::*;
  use frame_system::{pallet_prelude::*, RawOrigin};
  use frame_support::{pallet_prelude::*, sp_runtime::SaturatedConversion};

  use sp_std::{vec, vec::Vec};
  use sp_core::sr25519::Signature;
  use sp_application_crypto::RuntimePublic;

  use dex_pallet::{Pallet as Dex, Config as DexConfig};
  use coins_pallet::{Config as CoinsConfig, Pallet as Coins};
  use validator_sets_pallet::{Config as VsConfig, Pallet as ValidatorSets};

  use economic_security_pallet::{Config as EconomicSecurityConfig, Pallet as EconomicSecurity};

  use serai_primitives::*;
  use validator_sets_primitives::{ValidatorSet, musig_key};
  pub use genesis_liquidity_primitives as primitives;
  use primitives::*;

  // TODO: Have a more robust way of accessing LiquidityTokens pallet.
  /// LiquidityTokens Pallet as an instance of coins pallet.
  pub type LiquidityTokens<T> = coins_pallet::Pallet<T, coins_pallet::Instance1>;

  #[pallet::config]
  pub trait Config:
    frame_system::Config
    + VsConfig
    + DexConfig
    + EconomicSecurityConfig
    + CoinsConfig
    + coins_pallet::Config<coins_pallet::Instance1>
  {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::error]
  pub enum Error<T> {
    GenesisPeriodEnded,
    AmountOverflowed,
    NotEnoughLiquidity,
    CanOnlyRemoveFullAmount,
  }

  #[pallet::event]
  #[pallet::generate_deposit(fn deposit_event)]
  pub enum Event<T: Config> {
    GenesisLiquidityAdded { by: SeraiAddress, balance: ExternalBalance },
    GenesisLiquidityRemoved { by: SeraiAddress, balance: ExternalBalance },
    GenesisLiquidityAddedToPool { coin: ExternalBalance, sri: Amount },
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  /// Keeps shares and the amount of coins per account.
  #[pallet::storage]
  #[pallet::getter(fn liquidity)]
  pub(crate) type Liquidity<T: Config> = StorageDoubleMap<
    _,
    Identity,
    ExternalCoin,
    Blake2_128Concat,
    PublicKey,
    LiquidityAmount,
    OptionQuery,
  >;

  /// Keeps the total shares and the total amount of coins per coin.
  #[pallet::storage]
  #[pallet::getter(fn supply)]
  pub(crate) type Supply<T: Config> =
    StorageMap<_, Identity, ExternalCoin, LiquidityAmount, OptionQuery>;

  #[pallet::storage]
  pub(crate) type Oracle<T: Config> = StorageMap<_, Identity, ExternalCoin, u64, OptionQuery>;

  #[pallet::storage]
  #[pallet::getter(fn genesis_complete_block)]
  pub(crate) type GenesisCompleteBlock<T: Config> = StorageValue<_, u64, OptionQuery>;

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(n: BlockNumberFor<T>) -> Weight {
      // Distribute the genesis sri to pools after a month
      if (n.saturated_into::<u64>() >= MONTHS) &&
        Self::oraclization_is_done() &&
        GenesisCompleteBlock::<T>::get().is_none()
      {
        // mint the SRI
        Coins::<T>::mint(
          GENESIS_LIQUIDITY_ACCOUNT.into(),
          Balance { coin: Coin::Serai, amount: Amount(GENESIS_SRI) },
        )
        .unwrap();

        // get pool & total values
        let mut pool_values = vec![];
        let mut total_value: u128 = 0;
        for coin in EXTERNAL_COINS {
          // initial coin value in terms of btc
          let Some(value) = Oracle::<T>::get(coin) else {
            continue;
          };

          let pool_amount =
            u128::from(Supply::<T>::get(coin).unwrap_or(LiquidityAmount::zero()).coins);
          let pool_value = pool_amount
            .checked_mul(value.into())
            .unwrap()
            .checked_div(10u128.pow(coin.decimals()))
            .unwrap();
          total_value = total_value.checked_add(pool_value).unwrap();
          pool_values.push((coin, pool_amount, pool_value));
        }

        // add the liquidity per pool
        let mut total_sri_distributed = 0;
        let pool_values_len = pool_values.len();
        for (i, (coin, pool_amount, pool_value)) in pool_values.into_iter().enumerate() {
          // whatever sri left for the last coin should be ~= it's ratio
          let sri_amount = if i == (pool_values_len - 1) {
            GENESIS_SRI.checked_sub(total_sri_distributed).unwrap()
          } else {
            u64::try_from(
              u128::from(GENESIS_SRI)
                .checked_mul(pool_value)
                .unwrap()
                .checked_div(total_value)
                .unwrap(),
            )
            .unwrap()
          };
          total_sri_distributed = total_sri_distributed.checked_add(sri_amount).unwrap();

          // actually add the liquidity to dex
          let origin = RawOrigin::Signed(GENESIS_LIQUIDITY_ACCOUNT.into());
          let Ok(()) = Dex::<T>::add_liquidity(
            origin.into(),
            coin,
            u64::try_from(pool_amount).unwrap(),
            sri_amount,
            u64::try_from(pool_amount).unwrap(),
            sri_amount,
            GENESIS_LIQUIDITY_ACCOUNT.into(),
          ) else {
            continue;
          };

          // let everyone know about the event
          Self::deposit_event(Event::GenesisLiquidityAddedToPool {
            coin: ExternalBalance { coin, amount: Amount(u64::try_from(pool_amount).unwrap()) },
            sri: Amount(sri_amount),
          });
        }
        assert_eq!(total_sri_distributed, GENESIS_SRI);

        // we shouldn't have left any coin in genesis account at this moment, including SRI.
        // All transferred to the pools.
        for coin in COINS {
          assert_eq!(Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), coin), Amount(0));
        }

        GenesisCompleteBlock::<T>::set(Some(n.saturated_into::<u64>()));
      }

      Weight::zero() // TODO
    }
  }

  impl<T: Config> Pallet<T> {
    /// Add genesis liquidity for the given account. All accounts that provide liquidity
    /// will receive the genesis SRI according to their liquidity ratio.
    pub fn add_coin_liquidity(account: PublicKey, balance: ExternalBalance) -> DispatchResult {
      // check we are still in genesis period
      if Self::genesis_ended() {
        Err(Error::<T>::GenesisPeriodEnded)?;
      }

      // calculate new shares & supply
      let (new_liquidity, new_supply) = if let Some(supply) = Supply::<T>::get(balance.coin) {
        // calculate amount of shares for this amount
        let shares = Self::mul_div(supply.shares, balance.amount.0, supply.coins)?;

        // get new shares for this account
        let existing =
          Liquidity::<T>::get(balance.coin, account).unwrap_or(LiquidityAmount::zero());
        (
          LiquidityAmount {
            shares: existing.shares.checked_add(shares).ok_or(Error::<T>::AmountOverflowed)?,
            coins: existing
              .coins
              .checked_add(balance.amount.0)
              .ok_or(Error::<T>::AmountOverflowed)?,
          },
          LiquidityAmount {
            shares: supply.shares.checked_add(shares).ok_or(Error::<T>::AmountOverflowed)?,
            coins: supply
              .coins
              .checked_add(balance.amount.0)
              .ok_or(Error::<T>::AmountOverflowed)?,
          },
        )
      } else {
        let first_amount =
          LiquidityAmount { shares: INITIAL_GENESIS_LP_SHARES, coins: balance.amount.0 };
        (first_amount, first_amount)
      };

      // save
      Liquidity::<T>::set(balance.coin, account, Some(new_liquidity));
      Supply::<T>::set(balance.coin, Some(new_supply));
      Self::deposit_event(Event::GenesisLiquidityAdded { by: account.into(), balance });
      Ok(())
    }

    /// Returns the number of blocks since the all networks reached economic security first time.
    /// If networks is yet to be reached that threshold, None is returned.
    fn blocks_since_ec_security() -> Option<u64> {
      let mut min = u64::MAX;
      for n in EXTERNAL_NETWORKS {
        let ec_security_block =
          EconomicSecurity::<T>::economic_security_block(n)?.saturated_into::<u64>();
        let current = <frame_system::Pallet<T>>::block_number().saturated_into::<u64>();
        let diff = current.saturating_sub(ec_security_block);
        min = diff.min(min);
      }
      Some(min)
    }

    fn genesis_ended() -> bool {
      Self::oraclization_is_done() &&
        <frame_system::Pallet<T>>::block_number().saturated_into::<u64>() >= MONTHS
    }

    fn oraclization_is_done() -> bool {
      for c in EXTERNAL_COINS {
        if Oracle::<T>::get(c).is_none() {
          return false;
        }
      }

      true
    }

    fn mul_div(a: u64, b: u64, c: u64) -> Result<u64, Error<T>> {
      let a = u128::from(a);
      let b = u128::from(b);
      let c = u128::from(c);

      let result = a
        .checked_mul(b)
        .ok_or(Error::<T>::AmountOverflowed)?
        .checked_div(c)
        .ok_or(Error::<T>::AmountOverflowed)?;

      result.try_into().map_err(|_| Error::<T>::AmountOverflowed)
    }
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Remove the provided genesis liquidity for an account.
    #[pallet::call_index(0)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn remove_coin_liquidity(origin: OriginFor<T>, balance: ExternalBalance) -> DispatchResult {
      let account = ensure_signed(origin)?;
      let origin = RawOrigin::Signed(GENESIS_LIQUIDITY_ACCOUNT.into());
      let supply = Supply::<T>::get(balance.coin).ok_or(Error::<T>::NotEnoughLiquidity)?;

      // check we are still in genesis period
      let (new_liquidity, new_supply) = if Self::genesis_ended() {
        // see how much liq tokens we have
        let total_liq_tokens =
          LiquidityTokens::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), Coin::from(balance.coin))
            .0;

        // get how much user wants to remove
        let LiquidityAmount { shares, coins } =
          Liquidity::<T>::get(balance.coin, account).unwrap_or(LiquidityAmount::zero());
        let total_shares = Supply::<T>::get(balance.coin).unwrap_or(LiquidityAmount::zero()).shares;
        let user_liq_tokens = Self::mul_div(total_liq_tokens, shares, total_shares)?;
        let amount_to_remove_liq_tokens =
          Self::mul_div(user_liq_tokens, balance.amount.0, INITIAL_GENESIS_LP_SHARES)?;
        let amount_to_remove_shares =
          Self::mul_div(shares, balance.amount.0, INITIAL_GENESIS_LP_SHARES)?;

        // remove liquidity from pool
        let prev_sri = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), Coin::Serai);
        let prev_coin = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), balance.coin.into());
        Dex::<T>::remove_liquidity(
          origin.clone().into(),
          balance.coin,
          amount_to_remove_liq_tokens,
          1,
          1,
          GENESIS_LIQUIDITY_ACCOUNT.into(),
        )?;
        let current_sri = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), Coin::Serai);
        let current_coin =
          Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), balance.coin.into());

        // burn the SRI if necessary
        // TODO: take into consideration movement between pools.
        let mut sri: u64 = current_sri.0.saturating_sub(prev_sri.0);
        let distance_to_full_pay =
          GENESIS_SRI_TRICKLE_FEED.saturating_sub(Self::blocks_since_ec_security().unwrap_or(0));
        let burn_sri_amount = Self::mul_div(sri, distance_to_full_pay, GENESIS_SRI_TRICKLE_FEED)?;
        Coins::<T>::burn(
          origin.clone().into(),
          Balance { coin: Coin::Serai, amount: Amount(burn_sri_amount) },
        )?;
        sri = sri.checked_sub(burn_sri_amount).ok_or(Error::<T>::AmountOverflowed)?;

        // transfer to owner
        let coin_out = current_coin.0.saturating_sub(prev_coin.0);
        Coins::<T>::transfer(
          origin.clone().into(),
          account,
          Balance { coin: balance.coin.into(), amount: Amount(coin_out) },
        )?;
        Coins::<T>::transfer(
          origin.into(),
          account,
          Balance { coin: Coin::Serai, amount: Amount(sri) },
        )?;

        // return new amounts
        (
          LiquidityAmount {
            shares: shares
              .checked_sub(amount_to_remove_shares)
              .ok_or(Error::<T>::AmountOverflowed)?,
            coins: coins.checked_sub(coin_out).ok_or(Error::<T>::AmountOverflowed)?,
          },
          LiquidityAmount {
            shares: supply
              .shares
              .checked_sub(amount_to_remove_shares)
              .ok_or(Error::<T>::AmountOverflowed)?,
            coins: supply.coins.checked_sub(coin_out).ok_or(Error::<T>::AmountOverflowed)?,
          },
        )
      } else {
        if balance.amount.0 != INITIAL_GENESIS_LP_SHARES {
          Err(Error::<T>::CanOnlyRemoveFullAmount)?;
        }
        let existing =
          Liquidity::<T>::get(balance.coin, account).ok_or(Error::<T>::NotEnoughLiquidity)?;

        // transfer to the user
        Coins::<T>::transfer(
          origin.into(),
          account,
          Balance { coin: balance.coin.into(), amount: Amount(existing.coins) },
        )?;

        (
          LiquidityAmount::zero(),
          LiquidityAmount {
            shares: supply
              .shares
              .checked_sub(existing.shares)
              .ok_or(Error::<T>::AmountOverflowed)?,
            coins: supply.coins.checked_sub(existing.coins).ok_or(Error::<T>::AmountOverflowed)?,
          },
        )
      };

      // save
      if new_liquidity == LiquidityAmount::zero() {
        Liquidity::<T>::set(balance.coin, account, None);
      } else {
        Liquidity::<T>::set(balance.coin, account, Some(new_liquidity));
      }
      Supply::<T>::set(balance.coin, Some(new_supply));

      Self::deposit_event(Event::GenesisLiquidityRemoved { by: account.into(), balance });
      Ok(())
    }

    /// A call to submit the initial coin values in terms of BTC.
    #[pallet::call_index(1)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn oraclize_values(
      origin: OriginFor<T>,
      values: Values,
      _signature: Signature,
    ) -> DispatchResult {
      ensure_none(origin)?;

      // set their relative values
      Oracle::<T>::set(ExternalCoin::Bitcoin, Some(10u64.pow(ExternalCoin::Bitcoin.decimals())));
      Oracle::<T>::set(ExternalCoin::Monero, Some(values.monero));
      Oracle::<T>::set(ExternalCoin::Ether, Some(values.ether));
      Oracle::<T>::set(ExternalCoin::Dai, Some(values.dai));
      Ok(())
    }
  }

  #[pallet::validate_unsigned]
  impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(_: TransactionSource, call: &Self::Call) -> TransactionValidity {
      match call {
        Call::oraclize_values { ref values, ref signature } => {
          let network = NetworkId::Serai;
          let Some(session) = ValidatorSets::<T>::session(network) else {
            return Err(TransactionValidityError::from(InvalidTransaction::Custom(0)));
          };

          let set = ValidatorSet { network, session };
          let signers = ValidatorSets::<T>::participants_for_latest_decided_set(network)
            .expect("no participant in the current set")
            .into_iter()
            .map(|(p, _)| p)
            .collect::<Vec<_>>();

          // check this didn't get called before
          if Self::oraclization_is_done() {
            Err(InvalidTransaction::Custom(1))?;
          }

          // make sure signers settings the value at the end of the genesis period.
          // we don't need this check for tests.
          #[cfg(not(feature = "fast-epoch"))]
          if <frame_system::Pallet<T>>::block_number().saturated_into::<u64>() < MONTHS {
            Err(InvalidTransaction::Custom(2))?;
          }

          if !musig_key(set, &signers).verify(&oraclize_values_message(&set, values), signature) {
            Err(InvalidTransaction::BadProof)?;
          }

          ValidTransaction::with_tag_prefix("GenesisLiquidity")
            .and_provides((0, set))
            .longevity(u64::MAX)
            .propagate(true)
            .build()
        }
        Call::remove_coin_liquidity { .. } => Err(InvalidTransaction::Call)?,
        Call::__Ignore(_, _) => unreachable!(),
      }
    }
  }
}

pub use pallet::*;
