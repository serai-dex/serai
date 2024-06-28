#![cfg_attr(not(feature = "std"), no_std)]

#[allow(clippy::cast_possible_truncation, clippy::no_effect_underscore_binding)]
#[frame_support::pallet]
pub mod pallet {
  use super::*;
  use frame_system::{pallet_prelude::*, RawOrigin};
  use frame_support::{pallet_prelude::*, sp_runtime::SaturatedConversion};

  use sp_std::{vec, vec::Vec};
  use sp_core::sr25519::Signature;
  use sp_application_crypto::RuntimePublic;

  use dex_pallet::{Pallet as Dex, Config as DexConfig};
  use coins_pallet::{Config as CoinsConfig, Pallet as Coins, AllowMint};
  use validator_sets_pallet::{Config as VsConfig, Pallet as ValidatorSets};

  use serai_primitives::{Coin, COINS, *};
  use validator_sets_primitives::{ValidatorSet, Session, musig_key};
  pub use genesis_liquidity_primitives as primitives;
  use primitives::*;

  /// LiquidityTokens Pallet as an instance of coins pallet.
  pub type LiquidityTokens<T> = coins_pallet::Pallet<T, coins_pallet::Instance1>;

  #[pallet::config]
  pub trait Config:
    frame_system::Config
    + VsConfig
    + DexConfig
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
    GenesisLiquidityAdded { by: SeraiAddress, balance: Balance },
    GenesisLiquidityRemoved { by: SeraiAddress, balance: Balance },
    GenesisLiquidityAddedToPool { coin1: Balance, coin2: Balance },
    EconomicSecurityReached { network: NetworkId },
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  #[pallet::storage]
  pub(crate) type Liquidity<T: Config> =
    StorageDoubleMap<_, Identity, Coin, Blake2_128Concat, PublicKey, SubstrateAmount, OptionQuery>;

  /// Keeps the total shares and the total amount of coins per coin.
  #[pallet::storage]
  pub(crate) type Supply<T: Config> = StorageMap<_, Identity, Coin, (u64, u64), OptionQuery>;

  #[pallet::storage]
  pub(crate) type EconomicSecurityReached<T: Config> =
    StorageMap<_, Identity, NetworkId, BlockNumberFor<T>, OptionQuery>;

  #[pallet::storage]
  pub(crate) type Oracle<T: Config> = StorageMap<_, Identity, Coin, u64, OptionQuery>;

  #[pallet::storage]
  pub(crate) type GenesisComplete<T: Config> = StorageValue<_, bool, OptionQuery>;

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_finalize(n: BlockNumberFor<T>) {
      #[cfg(feature = "fast-epoch")]
      let final_block = 10u64;

      #[cfg(not(feature = "fast-epoch"))]
      let final_block = MONTHS;

      // Distribute the genesis sri to pools after a month
      if n.saturated_into::<u64>() >= final_block &&
        Self::oraclization_is_done() &&
        GenesisComplete::<T>::get().is_none()
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
        for coin in COINS {
          if coin == Coin::Serai {
            continue;
          }

          // initial coin value in terms of btc
          let Some(value) = Oracle::<T>::get(coin) else {
            continue;
          };

          let pool_amount = u128::from(Supply::<T>::get(coin).unwrap_or((0, 0)).1);
          let pool_value = pool_amount.saturating_mul(value.into()) / 10u128.pow(coin.decimals());
          total_value = total_value.saturating_add(pool_value);
          pool_values.push((coin, pool_amount, pool_value));
        }

        // add the liquidity per pool
        let mut total_sri_distributed = 0;
        let pool_values_len = pool_values.len();
        for (i, (coin, pool_amount, pool_value)) in pool_values.into_iter().enumerate() {
          // whatever sri left for the last coin should be ~= it's ratio
          let sri_amount = if i == (pool_values_len - 1) {
            GENESIS_SRI - total_sri_distributed
          } else {
            u64::try_from(u128::from(GENESIS_SRI).saturating_mul(pool_value) / total_value).unwrap()
          };
          total_sri_distributed += sri_amount;

          // we can't add 0 liquidity
          if !(pool_amount > 0 && sri_amount > 0) {
            continue;
          }

          // actually add the liquidity to dex
          let origin = RawOrigin::Signed(GENESIS_LIQUIDITY_ACCOUNT.into());
          Dex::<T>::add_liquidity(
            origin.into(),
            coin,
            u64::try_from(pool_amount).unwrap(),
            sri_amount,
            u64::try_from(pool_amount).unwrap(),
            sri_amount,
            GENESIS_LIQUIDITY_ACCOUNT.into(),
          )
          .unwrap();

          // let everyone know about the event
          Self::deposit_event(Event::GenesisLiquidityAddedToPool {
            coin1: Balance { coin, amount: Amount(u64::try_from(pool_amount).unwrap()) },
            coin2: Balance { coin: Coin::Serai, amount: Amount(sri_amount) },
          });
        }
        assert_eq!(total_sri_distributed, GENESIS_SRI);

        // we shouldn't have left any coin in genesis account at this moment, including SRI.
        // All transferred to the pools.
        for coin in COINS {
          assert_eq!(Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), coin), Amount(0));
        }

        GenesisComplete::<T>::set(Some(true));
      }

      // we accept we reached economic security once we can mint smallest amount of a network's coin
      for coin in COINS {
        let existing = EconomicSecurityReached::<T>::get(coin.network());
        if existing.is_none() &&
          <T as CoinsConfig>::AllowMint::is_allowed(&Balance { coin, amount: Amount(1) })
        {
          EconomicSecurityReached::<T>::set(coin.network(), Some(n));
          Self::deposit_event(Event::EconomicSecurityReached { network: coin.network() });
        }
      }
    }
  }

  impl<T: Config> Pallet<T> {
    /// Add genesis liquidity for the given account. All accounts that provide liquidity
    /// will receive the genesis SRI according to their liquidity ratio.
    pub fn add_coin_liquidity(account: PublicKey, balance: Balance) -> DispatchResult {
      // check we are still in genesis period
      if Self::genesis_ended() {
        Err(Error::<T>::GenesisPeriodEnded)?;
      }

      // mint the coins
      Coins::<T>::mint(GENESIS_LIQUIDITY_ACCOUNT.into(), balance)?;

      // calculate new shares & supply
      let (new_shares, new_supply) = if let Some(supply) = Supply::<T>::get(balance.coin) {
        // calculate amount of shares for this amount
        let shares = Self::mul_div(supply.0, balance.amount.0, supply.1)?;

        // get new shares for this account
        let existing = Liquidity::<T>::get(balance.coin, account).unwrap_or(0);
        let new = existing.checked_add(shares).ok_or(Error::<T>::AmountOverflowed)?;

        (
          new,
          (
            supply.0.checked_add(shares).ok_or(Error::<T>::AmountOverflowed)?,
            supply.1.checked_add(balance.amount.0).ok_or(Error::<T>::AmountOverflowed)?,
          ),
        )
      } else {
        (GENESIS_LP_SHARES, (GENESIS_LP_SHARES, balance.amount.0))
      };

      // save
      Liquidity::<T>::set(balance.coin, account, Some(new_shares));
      Supply::<T>::set(balance.coin, Some(new_supply));
      Self::deposit_event(Event::GenesisLiquidityAdded { by: account.into(), balance });
      Ok(())
    }

    /// Returns the number of blocks since the all networks reached economic security first time.
    /// If networks is yet to be reached that threshold, None is returned.
    fn blocks_since_ec_security() -> Option<u64> {
      let mut min = u64::MAX;
      for n in NETWORKS {
        let ec_security_block = EconomicSecurityReached::<T>::get(n)?.saturated_into::<u64>();
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
      for c in COINS {
        if c == Coin::Serai {
          continue;
        }

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
    pub fn remove_coin_liquidity(origin: OriginFor<T>, balance: Balance) -> DispatchResult {
      let account = ensure_signed(origin)?;
      let origin = RawOrigin::Signed(GENESIS_LIQUIDITY_ACCOUNT.into());

      // check we are still in genesis period
      if Self::genesis_ended() {
        // see how much liq tokens we have
        let total_liq_tokens =
          LiquidityTokens::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), Coin::Serai).0;

        // get how much user wants to remove
        let user_shares = Liquidity::<T>::get(balance.coin, account).unwrap_or(0);
        let total_shares = Supply::<T>::get(balance.coin).unwrap_or((0, 0)).0;
        let user_liq_tokens = Self::mul_div(total_liq_tokens, user_shares, total_shares)?;
        let amount_to_remove = Self::mul_div(user_liq_tokens, balance.amount.0, GENESIS_LP_SHARES)?;

        // remove liquidity from pool
        let prev_sri = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), Coin::Serai);
        let prev_coin = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), balance.coin);
        Dex::<T>::remove_liquidity(
          origin.clone().into(),
          balance.coin,
          amount_to_remove,
          1,
          1,
          GENESIS_LIQUIDITY_ACCOUNT.into(),
        )?;
        let current_sri = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), Coin::Serai);
        let current_coin = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), balance.coin);

        // burn the SRI if necessary
        // TODO: take into consideration movement between pools.
        let mut sri = current_sri.0.saturating_sub(prev_sri.0);
        let distance_to_full_pay =
          GENESIS_SRI_TRICKLE_FEED.saturating_sub(Self::blocks_since_ec_security().unwrap_or(0));
        let burn_sri_amount = sri.saturating_mul(distance_to_full_pay) / GENESIS_SRI_TRICKLE_FEED;
        Coins::<T>::burn(
          origin.clone().into(),
          Balance { coin: Coin::Serai, amount: Amount(burn_sri_amount) },
        )?;
        sri -= burn_sri_amount;

        // transfer to owner
        let coin_out = current_coin.0 - prev_coin.0;
        Coins::<T>::transfer(
          origin.clone().into(),
          account,
          Balance { coin: balance.coin, amount: Amount(coin_out) },
        )?;
        Coins::<T>::transfer(
          origin.into(),
          account,
          Balance { coin: Coin::Serai, amount: Amount(sri) },
        )?;

        // save
        let new_shares =
          user_shares.checked_sub(amount_to_remove).ok_or(Error::<T>::AmountOverflowed)?;
        if new_shares == 0 {
          Liquidity::<T>::set(balance.coin, account, None);
        } else {
          Liquidity::<T>::set(balance.coin, account, Some(new_shares));
        }
      } else {
        let existing = Liquidity::<T>::get(balance.coin, account).unwrap_or(0);
        if balance.amount.0 > existing || balance.amount.0 == 0 {
          Err(Error::<T>::NotEnoughLiquidity)?;
        }
        if balance.amount.0 < existing {
          Err(Error::<T>::CanOnlyRemoveFullAmount)?;
        }

        // TODO: do external transfer instead for making it easier for the user?
        // or do we even want to make it easier?
        Coins::<T>::transfer(origin.into(), account, balance)?;

        // save
        Liquidity::<T>::set(balance.coin, account, None);
      }

      Self::deposit_event(Event::GenesisLiquidityRemoved { by: account.into(), balance });
      Ok(())
    }

    /// A call to submit the initial coin values in terms of BTC.
    #[pallet::call_index(1)]
    #[pallet::weight((0, DispatchClass::Operational))] // TODO
    pub fn set_initial_price(
      origin: OriginFor<T>,
      prices: Prices,
      _signature: Signature,
    ) -> DispatchResult {
      ensure_none(origin)?;

      // set the prices
      Oracle::<T>::set(Coin::Bitcoin, Some(prices.bitcoin));
      Oracle::<T>::set(Coin::Monero, Some(prices.monero));
      Oracle::<T>::set(Coin::Ether, Some(prices.ethereum));
      Oracle::<T>::set(Coin::Dai, Some(prices.dai));
      Ok(())
    }
  }

  #[pallet::validate_unsigned]
  impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(_: TransactionSource, call: &Self::Call) -> TransactionValidity {
      match call {
        Call::set_initial_price { ref prices, ref signature } => {
          // TODO: if this is supposed to be called after a month, serai set won't still be
          // in the session 0? Ideally this should pull the session from Vs pallet?
          let set = ValidatorSet { network: NetworkId::Serai, session: Session(0) };
          let signers = ValidatorSets::<T>::participants_for_latest_decided_set(NetworkId::Serai)
            .expect("no participant in the current set")
            .into_iter()
            .map(|(p, _)| p)
            .collect::<Vec<_>>();

          // check this didn't get called before
          if Self::oraclization_is_done() {
            Err(InvalidTransaction::Custom(0))?;
          }

          // make sure signers settings the price at the end of the genesis period.
          // we don't need this check for tests.
          #[cfg(not(feature = "fast-epoch"))]
          if <frame_system::Pallet<T>>::block_number().saturated_into::<u64>() < MONTHS {
            Err(InvalidTransaction::Custom(1))?;
          }

          if !musig_key(set, &signers).verify(&set_initial_price_message(&set, prices), signature) {
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
