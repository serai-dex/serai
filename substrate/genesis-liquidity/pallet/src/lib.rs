#![cfg_attr(not(feature = "std"), no_std)]

#[allow(clippy::cast_possible_truncation, clippy::no_effect_underscore_binding)]
#[frame_support::pallet]
pub mod pallet {
  use super::*;
  use frame_system::{pallet_prelude::*, RawOrigin};
  use frame_support::{pallet_prelude::*, sp_runtime::SaturatedConversion};

  use sp_std::{vec, collections::btree_map::BTreeMap};

  use dex_pallet::{Pallet as Dex, Config as DexConfig};
  use coins_pallet::{
    primitives::{OutInstructionWithBalance, OutInstruction},
    Config as CoinsConfig, Pallet as Coins, AllowMint,
  };

  use serai_primitives::*;
  pub use genesis_liquidity_primitives as primitives;
  use primitives::*;

  /// LiquidityTokens Pallet as an instance of coins pallet.
  pub type LiquidityTokens<T> = coins_pallet::Pallet<T, coins_pallet::Instance1>;

  #[pallet::config]
  pub trait Config:
    frame_system::Config + DexConfig + CoinsConfig + coins_pallet::Config<coins_pallet::Instance1>
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

  #[pallet::storage]
  pub(crate) type LiquidityTokensPerAddress<T: Config> =
    StorageDoubleMap<_, Identity, Coin, Blake2_128Concat, PublicKey, SubstrateAmount, OptionQuery>;

  #[pallet::storage]
  pub(crate) type EconomicSecurityReached<T: Config> =
    StorageMap<_, Identity, NetworkId, BlockNumberFor<T>, ValueQuery>;

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_finalize(n: BlockNumberFor<T>) {
      // Distribute the genesis sri to pools after a month
      if n == BLOCKS_PER_MONTH.into() {
        // mint the SRI
        Coins::<T>::mint(
          GENESIS_LIQUIDITY_ACCOUNT.into(),
          Balance { coin: Coin::Serai, amount: Amount(GENESIS_SRI) },
        )
        .unwrap();

        // get coin values & total
        let mut account_values = BTreeMap::new();
        let mut pool_values = BTreeMap::new();
        let mut total_value: u64 = 0;
        for coin in COINS {
          // TODO: following line is just a place holder till we get the actual coin value
          // in terms of btc.
          let value = Dex::<T>::security_oracle_value(coin).unwrap_or(Amount(0)).0;
          account_values.insert(coin, vec![]);
          let mut pool_amount: u64 = 0;
          for (account, amount) in Liquidity::<T>::iter_prefix(coin) {
            pool_amount = pool_amount.saturating_add(amount);
            let value_this_addr = amount.saturating_mul(value);
            account_values.get_mut(&coin).unwrap().push((account, value_this_addr))
          }

          let pool_value = pool_amount.saturating_mul(value);
          total_value = total_value.saturating_add(pool_value);
          pool_values.insert(coin, (pool_amount, pool_value));
        }

        // add the liquidity per pool
        for (coin, (amount, value)) in &pool_values {
          let sri_amount = GENESIS_SRI.saturating_mul(*value) / total_value;
          let origin = RawOrigin::Signed(GENESIS_LIQUIDITY_ACCOUNT.into());
          Dex::<T>::add_liquidity(
            origin.into(),
            *coin,
            *amount,
            sri_amount,
            *amount,
            sri_amount,
            GENESIS_LIQUIDITY_ACCOUNT.into(),
          )
          .unwrap();
          Self::deposit_event(Event::GenesisLiquidityAddedToPool {
            coin1: Balance { coin: *coin, amount: Amount(*amount) },
            coin2: Balance { coin: Coin::Serai, amount: Amount(sri_amount) },
          });

          // set liquidity tokens per account
          let tokens = LiquidityTokens::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), *coin).0;
          let mut total_tokens_this_coin: u64 = 0;
          for (acc, value) in account_values.get(coin).unwrap() {
            let liq_tokens_this_acc = tokens.saturating_mul(*value) / pool_values.get(coin).unwrap().1;
            total_tokens_this_coin = total_tokens_this_coin.saturating_add(liq_tokens_this_acc);
            LiquidityTokensPerAddress::<T>::set(coin, acc, Some(liq_tokens_this_acc));
          }
          assert_eq!(tokens, total_tokens_this_coin);
        }

        // we shouldn't have any coin left in our account at this moment, including SRI.
        for coin in COINS {
          assert_eq!(Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), coin), Amount(0));
        }
      }

      // we accept we reached economic security once we can mint smallest amount of a network's coin
      for coin in COINS {
        let existing = EconomicSecurityReached::<T>::get(coin.network());
        if existing == 0u32.into() &&
          <T as CoinsConfig>::AllowMint::is_allowed(&Balance { coin, amount: Amount(1) })
        {
          EconomicSecurityReached::<T>::set(coin.network(), n);
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

      // save
      let existing = Liquidity::<T>::get(balance.coin, account).unwrap_or(0);
      let new = existing.checked_add(balance.amount.0).ok_or(Error::<T>::AmountOverflowed)?;
      Liquidity::<T>::set(balance.coin, account, Some(new));

      Self::deposit_event(Event::GenesisLiquidityAdded { by: account.into(), balance });
      Ok(())
    }

    /// Remove the provided genesis liquidity for an account. If called pre-economic security era,
    pub fn remove_coin_liquidity(
      account: PublicKey,
      balance: Balance,
      out_address: ExternalAddress,
    ) -> DispatchResult {
      let origin = RawOrigin::Signed(GENESIS_LIQUIDITY_ACCOUNT.into());

      // check we are still in genesis period
      if Self::genesis_ended() {
        // check user have enough to remove
        let existing = LiquidityTokensPerAddress::<T>::get(balance.coin, account).unwrap_or(0);
        if balance.amount.0 > existing {
          Err(Error::<T>::NotEnoughLiquidity)?;
        }

        // remove liquidity from pool
        let prev_sri = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), Coin::Serai);
        let prev_coin = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), balance.coin);
        Dex::<T>::remove_liquidity(
          origin.clone().into(),
          balance.coin,
          balance.amount.0,
          1,
          1,
          GENESIS_LIQUIDITY_ACCOUNT.into(),
        )?;
        let current_sri = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), Coin::Serai);
        let current_coin = Coins::<T>::balance(GENESIS_LIQUIDITY_ACCOUNT.into(), balance.coin);

        // burn the SRI if necessary
        let mut sri = current_sri.0.saturating_sub(prev_sri.0);
        let burn_sri_amount = sri.saturating_mul(
          GENESIS_SRI_TRICKLE_FEED - Self::blocks_since_ec_security(&balance.coin),
        ) / GENESIS_SRI_TRICKLE_FEED;
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
        let existing = LiquidityTokensPerAddress::<T>::get(balance.coin, account).unwrap_or(0);
        let new = existing.checked_sub(balance.amount.0).ok_or(Error::<T>::AmountOverflowed)?;
        LiquidityTokensPerAddress::<T>::set(balance.coin, account, Some(new));
      } else {
        let existing = Liquidity::<T>::get(balance.coin, account).unwrap_or(0);
        if balance.amount.0 > existing || balance.amount.0 == 0 {
          Err(Error::<T>::NotEnoughLiquidity)?;
        }
        if balance.amount.0 < existing {
          Err(Error::<T>::CanOnlyRemoveFullAmount)?;
        }

        // TODO: do internal transfer instead?
        let origin = RawOrigin::Signed(GENESIS_LIQUIDITY_ACCOUNT.into());
        let instruction = OutInstructionWithBalance {
          instruction: OutInstruction { address: out_address, data: None },
          balance,
        };
        Coins::<T>::burn_with_instruction(origin.into(), instruction)?;

        // save
        Liquidity::<T>::set(balance.coin, account, None);
      }

      Self::deposit_event(Event::GenesisLiquidityRemoved { by: account.into(), balance });
      Ok(())
    }

    /// Returns the number of blocks since the coin's network reached economic security first time.
    /// If the network is yet to be reached that threshold, 0 is returned. And maximum of
    /// `GENESIS_SRI_TRICKLE_FEED` returned.
    fn blocks_since_ec_security(coin: &Coin) -> u64 {
      let ec_security_block =
        EconomicSecurityReached::<T>::get(coin.network()).saturated_into::<u64>();
      let current = <frame_system::Pallet<T>>::block_number().saturated_into::<u64>();
      if ec_security_block > 0 {
        let diff = current - ec_security_block;
        if diff > GENESIS_SRI_TRICKLE_FEED {
          return GENESIS_SRI_TRICKLE_FEED;
        }

        return diff;
      }

      0
    }

    fn genesis_ended() -> bool {
      <frame_system::Pallet<T>>::block_number() >= BLOCKS_PER_MONTH.into()
    }
  }
}

pub use pallet::*;
