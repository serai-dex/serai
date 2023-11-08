// This file was originally:

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// It has been forked into a crate distributed under the AGPL 3.0.
// Please check the current distribution for up-to-date copyright and licensing information.

//! # Serai Dex pallet
//!
//! Serai Dex pallet based on the [Uniswap V2](https://github.com/Uniswap/v2-core) logic.
//!
//! ## Overview
//!
//! This pallet allows you to:
//!
//!  - [create a liquidity pool](`Pallet::create_pool()`) for 2 coins
//!  - [provide the liquidity](`Pallet::add_liquidity()`) and receive back an LP token
//!  - [exchange the LP token back to coins](`Pallet::remove_liquidity()`)
//!  - [swap a specific amount of coins for another](`Pallet::swap_exact_tokens_for_tokens()`) if
//!    there is a pool created, or
//!  - [swap some coins for a specific amount of
//!    another](`Pallet::swap_tokens_for_exact_tokens()`).
//!  - [query for an exchange price](`DexApi::quote_price_exact_tokens_for_tokens`) via
//!    a runtime call endpoint
//!  - [query the size of a liquidity pool](`DexApi::get_reserves`) via a runtime api
//!    endpoint.
//!
//! The `quote_price_exact_tokens_for_tokens` and `quote_price_tokens_for_exact_tokens` functions
//! both take a path parameter of the route to take. If you want to swap from native coin to
//! non-native coin 1, you would pass in a path of `[DOT, 1]` or `[1, DOT]`. If you want to swap
//! from non-native coin 1 to non-native coin 2, you would pass in a path of `[1, DOT, 2]`.
//!
//! (For an example of configuring this pallet to use `MultiLocation` as an coin id, see the
//! cumulus repo).
//!
//! Here is an example `state_call` that asks for a quote of a pool of native versus coin 1:
//!
//! ```text
//! curl -sS -H "Content-Type: application/json" -d \
//! '{
//!    "id": 1,
//!    "jsonrpc": "2.0",
//!    "method": "state_call",
//!    "params": [
//!      "DexApi_quote_price_tokens_for_exact_tokens",
//!      "0x0101000000000000000000000011000000000000000000"
//!    ]
//! }' \
//! http://localhost:9933/
//! ```
//! (This can be run against the kitchen sync node in the `node` folder of this repo.)
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]
use frame_support::traits::DefensiveOption;

// #[cfg(feature = "runtime-benchmarks")]
// mod benchmarking;

pub mod weights;

// #[cfg(test)]
// mod tests;

// #[cfg(test)]
// mod mock;

use frame_support::ensure;
use frame_system::{
  ensure_signed,
  pallet_prelude::{BlockNumberFor, OriginFor},
};

pub use pallet::*;

use sp_arithmetic::traits::Unsigned;
use sp_runtime::{
  traits::{CheckedAdd, CheckedDiv, CheckedMul, CheckedSub, Ensure, TrailingZeroInput},
  DispatchError,
};

use serai_primitives::{Coin, SubstrateAmount};

use sp_std::prelude::*;
use dex_primitives::*;
pub use weights::WeightInfo;

#[frame_support::pallet]
pub mod pallet {
  use super::*;
  use frame_support::{pallet_prelude::*, BoundedBTreeSet};

  use sp_core::sr25519::Public;
  use sp_runtime::{
    traits::{IntegerSquareRoot, One, Zero},
    Saturating,
  };

  use coins_pallet::{Pallet as CoinsPallet, Config as CoinsConfig};

  use serai_primitives::{Coin, Amount, Balance, SubstrateAmount};

  /// Pool ID.
  ///
  /// The pool's `AccountId` is derived from this type. Any changes to the type may necessitate a
  /// migration.
  pub type PoolId = Coin;

  /// Liquidity token id is the same as pool id.
  pub type PoolCoinId = Coin;

  /// LiquidityTokens Pallet as an instance of coins pallet.
  pub type LiquidityTokens<T> = coins_pallet::Pallet<T, coins_pallet::Instance1>;

  #[pallet::pallet]
  pub struct Pallet<T>(_);

  #[pallet::config]
  pub trait Config:
    frame_system::Config<AccountId = Public>
    + CoinsConfig
    + coins_pallet::Config<coins_pallet::Instance1>
  {
    /// Overarching event type.
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

    /// A type used for conversions between `SubstrateAmount` and `SubstrateAmount`.
    type HigherPrecisionBalance: IntegerSquareRoot
      + One
      + Ensure
      + Unsigned
      + From<u32>
      + From<SubstrateAmount>
      + TryInto<SubstrateAmount>;

    /// A % the liquidity providers will take of every swap. Represents 10ths of a percent.
    #[pallet::constant]
    type LPFee: Get<u32>;

    /// The minimum LP token amount that could be minted. Ameliorates rounding errors.
    #[pallet::constant]
    type MintMinLiquidity: Get<SubstrateAmount>;

    /// The max number of hops in a swap.
    #[pallet::constant]
    type MaxSwapPathLength: Get<u32>;

    /// Weight information for extrinsics in this pallet.
    type WeightInfo: WeightInfo;

    /// The benchmarks need a way to create coin ids from u32s.
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper: BenchmarkHelper<PoolCoinId, PoolCoinId>;
  }

  /// Map from `PoolCoinId` to `PoolInfo`. This establishes whether a pool has been officially
  /// created rather than people sending tokens directly to a pool's public account.
  #[pallet::storage]
  pub type Pools<T: Config> = StorageMap<_, Blake2_128Concat, PoolId, PoolInfo<Coin>, OptionQuery>;

  // Pallet's events.
  #[pallet::event]
  #[pallet::generate_deposit(pub(super) fn deposit_event)]
  pub enum Event<T: Config> {
    /// A successful call of the `CretaPool` extrinsic will create this event.
    PoolCreated {
      /// The pool id associated with the pool. Note that the order of the coins may not be
      /// the same as the order specified in the create pool extrinsic.
      pool_id: PoolId,
      /// The account ID of the pool.
      pool_account: T::AccountId,
      /// The id of the liquidity tokens that will be minted when coins are added to this
      /// pool.
      lp_token: PoolCoinId,
    },

    /// A successful call of the `AddLiquidity` extrinsic will create this event.
    LiquidityAdded {
      /// The account that the liquidity was taken from.
      who: T::AccountId,
      /// The account that the liquidity tokens were minted to.
      mint_to: T::AccountId,
      /// The pool id of the pool that the liquidity was added to.
      pool_id: PoolId,
      /// The amount of the coin that was added to the pool.
      coin_amount: SubstrateAmount,
      /// The amount of the SRI that was added to the pool.
      sri_amount: SubstrateAmount,
      /// The id of the lp token that was minted.
      lp_token: PoolCoinId,
      /// The amount of lp tokens that were minted of that id.
      lp_token_minted: SubstrateAmount,
    },

    /// A successful call of the `RemoveLiquidity` extrinsic will create this event.
    LiquidityRemoved {
      /// The account that the liquidity tokens were burned from.
      who: T::AccountId,
      /// The account that the coins were transferred to.
      withdraw_to: T::AccountId,
      /// The pool id that the liquidity was removed from.
      pool_id: PoolId,
      /// The amount of the first coin that was removed from the pool.
      coin_amount: SubstrateAmount,
      /// The amount of the second coin that was removed from the pool.
      sri_amount: SubstrateAmount,
      /// The id of the lp token that was burned.
      lp_token: PoolCoinId,
      /// The amount of lp tokens that were burned of that id.
      lp_token_burned: SubstrateAmount,
    },
    /// Coins have been converted from one to another. Both `SwapExactTokenForToken`
    /// and `SwapTokenForExactToken` will generate this event.
    SwapExecuted {
      /// Which account was the instigator of the swap.
      who: T::AccountId,
      /// The account that the coins were transferred to.
      send_to: T::AccountId,
      /// The route of coin ids that the swap went through.
      /// E.g. A -> SRI -> B
      path: BoundedVec<Coin, T::MaxSwapPathLength>,
      /// The amount of the first coin that was swapped.
      amount_in: SubstrateAmount,
      /// The amount of the second coin that was received.
      amount_out: SubstrateAmount,
    },
    /// An amount has been transferred from one account to another.
    Transfer {
      /// The account that the coins were transferred from.
      from: T::AccountId,
      /// The account that the coins were transferred to.
      to: T::AccountId,
      /// The balance that was transferred.
      balance: Balance,
    },
  }

  #[pallet::genesis_config]
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
  pub struct GenesisConfig<T: Config> {
    /// Pools to create at launch.
    pub pools: Vec<Coin>,
    /// field just to have T. TODO: better way to own the T than this?
    pub ignore: PhantomData<T>,
  }

  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      GenesisConfig { pools: Default::default(), ignore: Default::default() }
    }
  }

  #[pallet::genesis_build]
  impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
    fn build(&self) {
      for coin in &self.pools {
        Pallet::<T>::create_pool(*coin).unwrap();
      }
    }
  }

  #[pallet::error]
  pub enum Error<T> {
    /// Provided coins are equal.
    EqualCoins,
    /// Provided coin is not supported for pool.
    UnsupportedCoin,
    /// Pool already exists.
    PoolExists,
    /// Desired amount can't be zero.
    WrongDesiredAmount,
    /// Provided amount should be greater than or equal to the existential deposit/coin's
    /// minimal amount.
    AmountOneLessThanMinimal,
    /// Provided amount should be greater than or equal to the existential deposit/coin's
    /// minimal amount.
    AmountTwoLessThanMinimal,
    /// Reserve needs to always be greater than or equal to the existential deposit/coin's
    /// minimal amount.
    ReserveLeftLessThanMinimal,
    /// Desired amount can't be equal to the pool reserve.
    AmountOutTooHigh,
    /// The pool doesn't exist.
    PoolNotFound,
    /// An overflow happened.
    Overflow,
    /// The minimal amount requirement for the first token in the pair wasn't met.
    CoinOneDepositDidNotMeetMinimum,
    /// The minimal amount requirement for the second token in the pair wasn't met.
    CoinTwoDepositDidNotMeetMinimum,
    /// The minimal amount requirement for the first token in the pair wasn't met.
    CoinOneWithdrawalDidNotMeetMinimum,
    /// The minimal amount requirement for the second token in the pair wasn't met.
    CoinTwoWithdrawalDidNotMeetMinimum,
    /// Optimal calculated amount is less than desired.
    OptimalAmountLessThanDesired,
    /// Insufficient liquidity minted.
    InsufficientLiquidityMinted,
    /// Requested liquidity can't be zero.
    ZeroLiquidity,
    /// Amount can't be zero.
    ZeroAmount,
    /// Insufficient liquidity in the pool.
    InsufficientLiquidity,
    /// Calculated amount out is less than provided minimum amount.
    ProvidedMinimumNotSufficientForSwap,
    /// Provided maximum amount is not sufficient for swap.
    ProvidedMaximumNotSufficientForSwap,
    /// Only pools with native on one side are valid.
    PoolMustContainNativeCurrency,
    /// The provided path must consists of 2 coins at least.
    InvalidPath,
    /// It was not possible to calculate path data.
    PathError,
    /// The provided path must consists of unique coins.
    NonUniquePath,
    /// It was not possible to get or increment the Id of the pool.
    IncorrectPoolCoinId,
    /// Unable to find an element in an array/vec that should have one-to-one correspondence
    /// with another. For example, an array of coins constituting a `path` should have a
    /// corresponding array of `amounts` along the path.
    CorrespondenceError,
  }

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn integrity_test() {
      assert!(T::MaxSwapPathLength::get() > 1, "the `MaxSwapPathLength` should be greater than 1",);
    }
  }

  impl<T: Config> Pallet<T> {
    /// Creates an empty liquidity pool and an associated new `lp_token` coin
    /// (the id of which is returned in the `Event::PoolCreated` event).
    ///
    /// Once a pool is created, someone may [`Pallet::add_liquidity`] to it.
    pub(crate) fn create_pool(coin: Coin) -> DispatchResult {
      ensure!(coin != Coin::Serai, Error::<T>::EqualCoins);

      // prepare pool_id
      let pool_id = Self::get_pool_id(coin, Coin::Serai).unwrap();
      ensure!(!Pools::<T>::contains_key(pool_id), Error::<T>::PoolExists);

      let pool_account = Self::get_pool_account(pool_id);
      frame_system::Pallet::<T>::inc_providers(&pool_account);

      let pool_info = PoolInfo { lp_token: coin };
      Pools::<T>::insert(pool_id, pool_info);

      Self::deposit_event(Event::PoolCreated { pool_id, pool_account, lp_token: coin });

      Ok(())
    }
  }

  /// Pallet's callable functions.
  #[pallet::call]
  impl<T: Config> Pallet<T> {
    /// Provide liquidity into the pool of `coin1` and `coin2`.
    /// NOTE: an optimal amount of coin1 and coin2 will be calculated and
    /// might be different than the provided `amount1_desired`/`amount2_desired`
    /// thus you should provide the min amount you're happy to provide.
    /// Params `amount1_min`/`amount2_min` represent that.
    /// `mint_to` will be sent the liquidity tokens that represent this share of the pool.
    ///
    /// Once liquidity is added, someone may successfully call
    /// [`Pallet::swap_exact_tokens_for_tokens`] successfully.
    #[pallet::call_index(0)]
    #[pallet::weight(T::WeightInfo::add_liquidity())]
    #[allow(clippy::too_many_arguments)]
    pub fn add_liquidity(
      origin: OriginFor<T>,
      coin: Coin,
      coin_desired: SubstrateAmount,
      sri_desired: SubstrateAmount,
      coin_min: SubstrateAmount,
      sri_min: SubstrateAmount,
      mint_to: T::AccountId,
    ) -> DispatchResult {
      let sender = ensure_signed(origin)?;
      ensure!(
        sri_desired > Zero::zero() && coin_desired > Zero::zero(),
        Error::<T>::WrongDesiredAmount
      );
      ensure!(coin != Coin::Serai, Error::<T>::EqualCoins);

      let pool_id = Self::get_pool_id(coin, Coin::Serai).unwrap();

      let maybe_pool = Pools::<T>::get(pool_id);
      let pool = maybe_pool.as_ref().ok_or(Error::<T>::PoolNotFound)?;
      let pool_account = Self::get_pool_account(pool_id);

      let sri_reserve = Self::get_balance(&pool_account, Coin::Serai);
      let coin_reserve = Self::get_balance(&pool_account, coin);

      let sri_amount: SubstrateAmount;
      let coin_amount: SubstrateAmount;
      if sri_reserve.is_zero() || coin_reserve.is_zero() {
        sri_amount = sri_desired;
        coin_amount = coin_desired;
      } else {
        let coin_optimal = Self::quote(sri_desired, sri_reserve, coin_reserve)?;

        if coin_optimal <= coin_desired {
          ensure!(coin_optimal >= coin_min, Error::<T>::CoinTwoDepositDidNotMeetMinimum);
          sri_amount = sri_desired;
          coin_amount = coin_optimal;
        } else {
          let sri_optimal = Self::quote(coin_desired, coin_reserve, sri_reserve)?;
          ensure!(sri_optimal <= sri_desired, Error::<T>::OptimalAmountLessThanDesired);
          ensure!(sri_optimal >= sri_min, Error::<T>::CoinOneDepositDidNotMeetMinimum);
          sri_amount = sri_optimal;
          coin_amount = coin_desired;
        }
      }

      Self::validate_minimal_amount(sri_amount.saturating_add(sri_reserve), Coin::Serai)
        .map_err(|_| Error::<T>::AmountOneLessThanMinimal)?;
      Self::validate_minimal_amount(coin_amount.saturating_add(coin_reserve), coin)
        .map_err(|_| Error::<T>::AmountTwoLessThanMinimal)?;

      Self::transfer(
        &sender,
        &pool_account,
        Balance { coin: Coin::Serai, amount: Amount(sri_amount) },
      )?;
      Self::transfer(&sender, &pool_account, Balance { coin, amount: Amount(coin_amount) })?;

      let total_supply = LiquidityTokens::<T>::supply(coin);

      let lp_token_amount: SubstrateAmount;
      if total_supply.is_zero() {
        lp_token_amount = Self::calc_lp_amount_for_zero_supply(sri_amount, coin_amount)?;
        LiquidityTokens::<T>::mint(
          pool_account,
          Balance { coin, amount: Amount(T::MintMinLiquidity::get()) },
        )?;
      } else {
        let side1 = Self::mul_div(sri_amount, total_supply, sri_reserve)?;
        let side2 = Self::mul_div(coin_amount, total_supply, coin_reserve)?;
        lp_token_amount = side1.min(side2);
      }

      ensure!(
        lp_token_amount > T::MintMinLiquidity::get(),
        Error::<T>::InsufficientLiquidityMinted
      );

      LiquidityTokens::<T>::mint(mint_to, Balance { coin, amount: Amount(lp_token_amount) })?;

      Self::deposit_event(Event::LiquidityAdded {
        who: sender,
        mint_to,
        pool_id,
        coin_amount,
        sri_amount,
        lp_token: pool.lp_token,
        lp_token_minted: lp_token_amount,
      });

      Ok(())
    }

    /// Allows you to remove liquidity by providing the `lp_token_burn` tokens that will be
    /// burned in the process. With the usage of `amount1_min_receive`/`amount2_min_receive`
    /// it's possible to control the min amount of returned tokens you're happy with.
    #[pallet::call_index(1)]
    #[pallet::weight(T::WeightInfo::remove_liquidity())]
    pub fn remove_liquidity(
      origin: OriginFor<T>,
      coin: Coin,
      lp_token_burn: SubstrateAmount,
      coin_min_receive: SubstrateAmount,
      sri_min_receive: SubstrateAmount,
      withdraw_to: T::AccountId,
    ) -> DispatchResult {
      let sender = ensure_signed(origin)?;
      ensure!(coin != Coin::Serai, Error::<T>::EqualCoins);

      let pool_id = Self::get_pool_id(coin, Coin::Serai).unwrap();
      ensure!(lp_token_burn > Zero::zero(), Error::<T>::ZeroLiquidity);

      let maybe_pool = Pools::<T>::get(pool_id);
      let pool = maybe_pool.as_ref().ok_or(Error::<T>::PoolNotFound)?;

      let pool_account = Self::get_pool_account(pool_id);
      let sri_reserve = Self::get_balance(&pool_account, Coin::Serai);
      let coin_reserve = Self::get_balance(&pool_account, coin);

      let total_supply = LiquidityTokens::<T>::supply(coin);
      let lp_redeem_amount = lp_token_burn;

      let sri_amount = Self::mul_div(lp_redeem_amount, sri_reserve, total_supply)?;
      let coin_amount = Self::mul_div(lp_redeem_amount, coin_reserve, total_supply)?;

      ensure!(
        !sri_amount.is_zero() && sri_amount >= sri_min_receive,
        Error::<T>::CoinOneWithdrawalDidNotMeetMinimum
      );
      ensure!(
        !coin_amount.is_zero() && coin_amount >= coin_min_receive,
        Error::<T>::CoinTwoWithdrawalDidNotMeetMinimum
      );
      let sri_reserve_left = sri_reserve.saturating_sub(sri_amount);
      let coin_reserve_left = coin_reserve.saturating_sub(coin_amount);
      Self::validate_minimal_amount(sri_reserve_left, Coin::Serai)
        .map_err(|_| Error::<T>::ReserveLeftLessThanMinimal)?;
      Self::validate_minimal_amount(coin_reserve_left, coin)
        .map_err(|_| Error::<T>::ReserveLeftLessThanMinimal)?;

      // burn the provided lp token amount that includes the fee
      // TODO: burn lp_token? uhh another burn function?
      LiquidityTokens::<T>::burn_internal(sender, Balance { coin, amount: Amount(lp_token_burn) })?;

      Self::transfer(
        &pool_account,
        &withdraw_to,
        Balance { coin: Coin::Serai, amount: Amount(sri_amount) },
      )?;
      Self::transfer(&pool_account, &withdraw_to, Balance { coin, amount: Amount(coin_amount) })?;

      Self::deposit_event(Event::LiquidityRemoved {
        who: sender,
        withdraw_to,
        pool_id,
        coin_amount,
        sri_amount,
        lp_token: pool.lp_token,
        lp_token_burned: lp_token_burn,
      });

      Ok(())
    }

    /// Swap the exact amount of `coin1` into `coin2`.
    /// `amount_out_min` param allows you to specify the min amount of the `coin2`
    /// you're happy to receive.
    ///
    /// [`DexApi::quote_price_exact_tokens_for_tokens`] runtime call can be called
    /// for a quote.
    #[pallet::call_index(2)]
    #[pallet::weight(T::WeightInfo::swap_exact_tokens_for_tokens())]
    pub fn swap_exact_tokens_for_tokens(
      origin: OriginFor<T>,
      path: BoundedVec<Coin, T::MaxSwapPathLength>,
      amount_in: SubstrateAmount,
      amount_out_min: SubstrateAmount,
      send_to: T::AccountId,
    ) -> DispatchResult {
      let sender = ensure_signed(origin)?;
      Self::do_swap_exact_tokens_for_tokens(
        sender,
        path,
        amount_in,
        Some(amount_out_min),
        send_to,
      )?;
      Ok(())
    }

    /// Swap any amount of `coin1` to get the exact amount of `coin2`.
    /// `amount_in_max` param allows to specify the max amount of the `coin1`
    /// you're happy to provide.
    ///
    /// [`DexApi::quote_price_tokens_for_exact_tokens`] runtime call can be called
    /// for a quote.
    #[pallet::call_index(3)]
    #[pallet::weight(T::WeightInfo::swap_tokens_for_exact_tokens())]
    pub fn swap_tokens_for_exact_tokens(
      origin: OriginFor<T>,
      path: BoundedVec<Coin, T::MaxSwapPathLength>,
      amount_out: SubstrateAmount,
      amount_in_max: SubstrateAmount,
      send_to: T::AccountId,
    ) -> DispatchResult {
      let sender = ensure_signed(origin)?;
      Self::do_swap_tokens_for_exact_tokens(
        sender,
        path,
        amount_out,
        Some(amount_in_max),
        send_to,
      )?;
      Ok(())
    }
  }

  impl<T: Config> Pallet<T> {
    /// Swap exactly `amount_in` of coin `path[0]` for coin `path[1]`.
    /// If an `amount_out_min` is specified, it will return an error if it is unable to acquire
    /// the amount desired.
    ///
    /// Withdraws the `path[0]` coin from `sender`, deposits the `path[1]` coin to `send_to`.
    ///
    /// If successful, returns the amount of `path[1]` acquired for the `amount_in`.
    pub fn do_swap_exact_tokens_for_tokens(
      sender: T::AccountId,
      path: BoundedVec<Coin, T::MaxSwapPathLength>,
      amount_in: SubstrateAmount,
      amount_out_min: Option<SubstrateAmount>,
      send_to: T::AccountId,
    ) -> Result<SubstrateAmount, DispatchError> {
      ensure!(amount_in > Zero::zero(), Error::<T>::ZeroAmount);
      if let Some(amount_out_min) = amount_out_min {
        ensure!(amount_out_min > Zero::zero(), Error::<T>::ZeroAmount);
      }

      Self::validate_swap_path(&path)?;

      let amounts = Self::get_amounts_out(amount_in, &path)?;
      let amount_out =
        *amounts.last().defensive_ok_or("get_amounts_out() returned an empty result")?;

      if let Some(amount_out_min) = amount_out_min {
        ensure!(amount_out >= amount_out_min, Error::<T>::ProvidedMinimumNotSufficientForSwap);
      }

      Self::do_swap(sender, &amounts, path, send_to)?;
      Ok(amount_out)
    }

    /// Take the `path[0]` coin and swap some amount for `amount_out` of the `path[1]`. If an
    /// `amount_in_max` is specified, it will return an error if acquiring `amount_out` would be
    /// too costly.
    ///
    /// Withdraws `path[0]` coin from `sender`, deposits the `path[1]` coin to `send_to`,
    ///
    /// If successful returns the amount of the `path[0]` taken to provide `path[1]`.
    pub fn do_swap_tokens_for_exact_tokens(
      sender: T::AccountId,
      path: BoundedVec<Coin, T::MaxSwapPathLength>,
      amount_out: SubstrateAmount,
      amount_in_max: Option<SubstrateAmount>,
      send_to: T::AccountId,
    ) -> Result<SubstrateAmount, DispatchError> {
      ensure!(amount_out > Zero::zero(), Error::<T>::ZeroAmount);
      if let Some(amount_in_max) = amount_in_max {
        ensure!(amount_in_max > Zero::zero(), Error::<T>::ZeroAmount);
      }

      Self::validate_swap_path(&path)?;

      let amounts = Self::get_amounts_in(amount_out, &path)?;
      let amount_in =
        *amounts.first().defensive_ok_or("get_amounts_in() returned an empty result")?;

      if let Some(amount_in_max) = amount_in_max {
        ensure!(amount_in <= amount_in_max, Error::<T>::ProvidedMaximumNotSufficientForSwap);
      }

      Self::do_swap(sender, &amounts, path, send_to)?;
      Ok(amount_in)
    }

    /// Transfer an `amount` of `coin_id`.
    fn transfer(
      from: &T::AccountId,
      to: &T::AccountId,
      balance: Balance,
    ) -> Result<Amount, DispatchError> {
      CoinsPallet::<T>::transfer_internal(*from, *to, balance)?;

      Self::deposit_event(Event::Transfer { from: *from, to: *to, balance });
      Ok(balance.amount)
    }

    /// Convert a `HigherPrecisionBalance` type to an `SubstrateAmount`.
    pub(crate) fn convert_hpb_to_coin_balance(
      amount: T::HigherPrecisionBalance,
    ) -> Result<SubstrateAmount, Error<T>> {
      amount.try_into().map_err(|_| Error::<T>::Overflow)
    }

    /// Swap coins along a `path`, depositing in `send_to`.
    pub(crate) fn do_swap(
      sender: T::AccountId,
      amounts: &Vec<SubstrateAmount>,
      path: BoundedVec<Coin, T::MaxSwapPathLength>,
      send_to: T::AccountId,
    ) -> Result<(), DispatchError> {
      ensure!(amounts.len() > 1, Error::<T>::CorrespondenceError);
      if let Some([coin1, coin2]) = &path.get(0 .. 2) {
        let pool_id = Self::get_pool_id(*coin1, *coin2)?;
        let pool_account = Self::get_pool_account(pool_id);
        // amounts should always contain a corresponding element to path.
        let first_amount = amounts.first().ok_or(Error::<T>::CorrespondenceError)?;

        Self::transfer(
          &sender,
          &pool_account,
          Balance { coin: *coin1, amount: Amount(*first_amount) },
        )?;

        let mut i = 0;
        let path_len = path.len() as u32;
        for coins_pair in path.windows(2) {
          if let [coin1, coin2] = coins_pair {
            let pool_id = Self::get_pool_id(*coin1, *coin2)?;
            let pool_account = Self::get_pool_account(pool_id);

            let amount_out =
              amounts.get((i + 1) as usize).ok_or(Error::<T>::CorrespondenceError)?;

            let to = if i < path_len - 2 {
              let coin3 = path.get((i + 2) as usize).ok_or(Error::<T>::PathError)?;
              Self::get_pool_account(Self::get_pool_id(*coin2, *coin3)?)
            } else {
              send_to
            };

            let reserve = Self::get_balance(&pool_account, *coin2);
            let reserve_left = reserve.saturating_sub(*amount_out);
            Self::validate_minimal_amount(reserve_left, *coin2)
              .map_err(|_| Error::<T>::ReserveLeftLessThanMinimal)?;

            Self::transfer(
              &pool_account,
              &to,
              Balance { coin: *coin2, amount: Amount(*amount_out) },
            )?;
          }
          i.saturating_inc();
        }
        Self::deposit_event(Event::SwapExecuted {
          who: sender,
          send_to,
          path,
          amount_in: *first_amount,
          amount_out: *amounts.last().expect("Always has more than 1 element"),
        });
      } else {
        return Err(Error::<T>::InvalidPath.into());
      }
      Ok(())
    }

    /// The account ID of the pool.
    ///
    /// This actually does computation. If you need to keep using it, then make sure you cache
    /// the value and only call this once.
    pub fn get_pool_account(pool_id: PoolId) -> T::AccountId {
      let encoded_pool_id = sp_io::hashing::blake2_256(&Encode::encode(&pool_id)[..]);

      Decode::decode(&mut TrailingZeroInput::new(encoded_pool_id.as_ref()))
        .expect("infinite length input; no invalid inputs for type; qed")
    }

    /// Get the `owner`'s balance of `coin`, which could be the chain's native coin or another
    /// fungible. Returns a value in the form of an `Amount`.
    fn get_balance(owner: &T::AccountId, coin: Coin) -> SubstrateAmount {
      CoinsPallet::<T>::balance(*owner, coin).0
    }

    /// Returns a pool id constructed from 2 coins.
    /// We expect deterministic order, so (coin1, coin2) or (coin2, coin1) returns the same
    /// result. Coins have to be different and one of them should be Coin::Serai.
    pub fn get_pool_id(coin1: Coin, coin2: Coin) -> Result<PoolId, Error<T>> {
      ensure!((coin1 == Coin::Serai) || (coin2 == Coin::Serai), Error::<T>::PoolNotFound);
      ensure!(coin1 != coin2, Error::<T>::PoolNotFound);
      if coin1 == Coin::Serai {
        Ok(coin2)
      } else {
        Ok(coin1)
      }
    }

    /// Returns the balance of each coin in the pool.
    /// The tuple result is in the order requested (not necessarily the same as pool order).
    pub fn get_reserves(
      coin1: &Coin,
      coin2: &Coin,
    ) -> Result<(SubstrateAmount, SubstrateAmount), Error<T>> {
      let pool_id = Self::get_pool_id(*coin1, *coin2)?;
      let pool_account = Self::get_pool_account(pool_id);

      let balance1 = Self::get_balance(&pool_account, *coin1);
      let balance2 = Self::get_balance(&pool_account, *coin2);

      if balance1.is_zero() || balance2.is_zero() {
        Err(Error::<T>::PoolNotFound)?;
      }

      Ok((balance1, balance2))
    }

    /// Leading to an amount at the end of a `path`, get the required amounts in.
    pub(crate) fn get_amounts_in(
      amount_out: SubstrateAmount,
      path: &BoundedVec<Coin, T::MaxSwapPathLength>,
    ) -> Result<Vec<SubstrateAmount>, DispatchError> {
      let mut amounts: Vec<SubstrateAmount> = vec![amount_out];

      for coins_pair in path.windows(2).rev() {
        if let [coin1, coin2] = coins_pair {
          let (reserve_in, reserve_out) = Self::get_reserves(coin1, coin2)?;
          let prev_amount = amounts.last().expect("Always has at least one element");
          let amount_in = Self::get_amount_in(*prev_amount, reserve_in, reserve_out)?;
          amounts.push(amount_in);
        }
      }

      amounts.reverse();
      Ok(amounts)
    }

    /// Following an amount into a `path`, get the corresponding amounts out.
    pub(crate) fn get_amounts_out(
      amount_in: SubstrateAmount,
      path: &BoundedVec<Coin, T::MaxSwapPathLength>,
    ) -> Result<Vec<SubstrateAmount>, DispatchError> {
      let mut amounts: Vec<SubstrateAmount> = vec![amount_in];

      for coins_pair in path.windows(2) {
        if let [coin1, coin2] = coins_pair {
          let (reserve_in, reserve_out) = Self::get_reserves(coin1, coin2)?;
          let prev_amount = amounts.last().expect("Always has at least one element");
          let amount_out = Self::get_amount_out(*prev_amount, reserve_in, reserve_out)?;
          amounts.push(amount_out);
        }
      }

      Ok(amounts)
    }

    /// Used by the RPC service to provide current prices.
    pub fn quote_price_exact_tokens_for_tokens(
      coin1: Coin,
      coin2: Coin,
      amount: SubstrateAmount,
      include_fee: bool,
    ) -> Option<SubstrateAmount> {
      let pool_id = Self::get_pool_id(coin1, coin2).ok()?;
      let pool_account = Self::get_pool_account(pool_id);

      let balance1 = Self::get_balance(&pool_account, coin1);
      let balance2 = Self::get_balance(&pool_account, coin2);
      if !balance1.is_zero() {
        if include_fee {
          Self::get_amount_out(amount, balance1, balance2).ok()
        } else {
          Self::quote(amount, balance1, balance2).ok()
        }
      } else {
        None
      }
    }

    /// Used by the RPC service to provide current prices.
    pub fn quote_price_tokens_for_exact_tokens(
      coin1: Coin,
      coin2: Coin,
      amount: SubstrateAmount,
      include_fee: bool,
    ) -> Option<SubstrateAmount> {
      let pool_id = Self::get_pool_id(coin1, coin2).ok()?;
      let pool_account = Self::get_pool_account(pool_id);

      let balance1 = Self::get_balance(&pool_account, coin1);
      let balance2 = Self::get_balance(&pool_account, coin2);
      if !balance1.is_zero() {
        if include_fee {
          Self::get_amount_in(amount, balance1, balance2).ok()
        } else {
          Self::quote(amount, balance2, balance1).ok()
        }
      } else {
        None
      }
    }

    /// Calculates the optimal amount from the reserves.
    pub fn quote(
      amount: SubstrateAmount,
      reserve1: SubstrateAmount,
      reserve2: SubstrateAmount,
    ) -> Result<SubstrateAmount, Error<T>> {
      // amount * reserve2 / reserve1
      Self::mul_div(amount, reserve2, reserve1)
    }

    pub(super) fn calc_lp_amount_for_zero_supply(
      amount1: SubstrateAmount,
      amount2: SubstrateAmount,
    ) -> Result<SubstrateAmount, Error<T>> {
      let amount1 = T::HigherPrecisionBalance::from(amount1);
      let amount2 = T::HigherPrecisionBalance::from(amount2);

      let result = amount1
        .checked_mul(&amount2)
        .ok_or(Error::<T>::Overflow)?
        .integer_sqrt()
        .checked_sub(&T::MintMinLiquidity::get().into())
        .ok_or(Error::<T>::InsufficientLiquidityMinted)?;

      result.try_into().map_err(|_| Error::<T>::Overflow)
    }

    fn mul_div(
      a: SubstrateAmount,
      b: SubstrateAmount,
      c: SubstrateAmount,
    ) -> Result<SubstrateAmount, Error<T>> {
      let a = T::HigherPrecisionBalance::from(a);
      let b = T::HigherPrecisionBalance::from(b);
      let c = T::HigherPrecisionBalance::from(c);

      let result = a
        .checked_mul(&b)
        .ok_or(Error::<T>::Overflow)?
        .checked_div(&c)
        .ok_or(Error::<T>::Overflow)?;

      result.try_into().map_err(|_| Error::<T>::Overflow)
    }

    /// Calculates amount out.
    ///
    /// Given an input amount of an coin and pair reserves, returns the maximum output amount
    /// of the other coin.
    pub fn get_amount_out(
      amount_in: SubstrateAmount,
      reserve_in: SubstrateAmount,
      reserve_out: SubstrateAmount,
    ) -> Result<SubstrateAmount, Error<T>> {
      let amount_in = T::HigherPrecisionBalance::from(amount_in);
      let reserve_in = T::HigherPrecisionBalance::from(reserve_in);
      let reserve_out = T::HigherPrecisionBalance::from(reserve_out);

      if reserve_in.is_zero() || reserve_out.is_zero() {
        return Err(Error::<T>::ZeroLiquidity);
      }

      let amount_in_with_fee = amount_in
        .checked_mul(&(T::HigherPrecisionBalance::from(1000u32) - (T::LPFee::get().into())))
        .ok_or(Error::<T>::Overflow)?;

      let numerator = amount_in_with_fee.checked_mul(&reserve_out).ok_or(Error::<T>::Overflow)?;

      let denominator = reserve_in
        .checked_mul(&1000u32.into())
        .ok_or(Error::<T>::Overflow)?
        .checked_add(&amount_in_with_fee)
        .ok_or(Error::<T>::Overflow)?;

      let result = numerator.checked_div(&denominator).ok_or(Error::<T>::Overflow)?;

      result.try_into().map_err(|_| Error::<T>::Overflow)
    }

    /// Calculates amount in.
    ///
    /// Given an output amount of an coin and pair reserves, returns a required input amount
    /// of the other coin.
    pub fn get_amount_in(
      amount_out: SubstrateAmount,
      reserve_in: SubstrateAmount,
      reserve_out: SubstrateAmount,
    ) -> Result<SubstrateAmount, Error<T>> {
      let amount_out = T::HigherPrecisionBalance::from(amount_out);
      let reserve_in = T::HigherPrecisionBalance::from(reserve_in);
      let reserve_out = T::HigherPrecisionBalance::from(reserve_out);

      if reserve_in.is_zero() || reserve_out.is_zero() {
        Err(Error::<T>::ZeroLiquidity)?
      }

      if amount_out >= reserve_out {
        Err(Error::<T>::AmountOutTooHigh)?
      }

      let numerator = reserve_in
        .checked_mul(&amount_out)
        .ok_or(Error::<T>::Overflow)?
        .checked_mul(&1000u32.into())
        .ok_or(Error::<T>::Overflow)?;

      let denominator = reserve_out
        .checked_sub(&amount_out)
        .ok_or(Error::<T>::Overflow)?
        .checked_mul(&(T::HigherPrecisionBalance::from(1000u32) - T::LPFee::get().into()))
        .ok_or(Error::<T>::Overflow)?;

      let result = numerator
        .checked_div(&denominator)
        .ok_or(Error::<T>::Overflow)?
        .checked_add(&One::one())
        .ok_or(Error::<T>::Overflow)?;

      result.try_into().map_err(|_| Error::<T>::Overflow)
    }

    /// Ensure that a `value` meets the minimum balance requirements of an `coin` class.
    fn validate_minimal_amount(value: SubstrateAmount, coin: Coin) -> Result<(), ()> {
      ensure!(value >= CoinsPallet::<T>::minimum_balance(coin).0, ());
      Ok(())
    }

    /// Ensure that a path is valid.
    fn validate_swap_path(
      path: &BoundedVec<Coin, T::MaxSwapPathLength>,
    ) -> Result<(), DispatchError> {
      ensure!(path.len() >= 2, Error::<T>::InvalidPath);

      // validate all the pools in the path are unique
      let mut pools = BoundedBTreeSet::<PoolId, T::MaxSwapPathLength>::new();
      for coins_pair in path.windows(2) {
        if let [coin1, coin2] = coins_pair {
          let pool_id = Self::get_pool_id(*coin1, *coin2)?;
          let new_element = pools.try_insert(pool_id).map_err(|_| Error::<T>::Overflow)?;
          if !new_element {
            return Err(Error::<T>::NonUniquePath.into());
          }
        }
      }
      Ok(())
    }
  }
}

impl<T: Config> Swap<T::AccountId, T::HigherPrecisionBalance, Coin> for Pallet<T> {
  fn swap_exact_tokens_for_tokens(
    sender: T::AccountId,
    path: Vec<Coin>,
    amount_in: T::HigherPrecisionBalance,
    amount_out_min: Option<T::HigherPrecisionBalance>,
    send_to: T::AccountId,
  ) -> Result<T::HigherPrecisionBalance, DispatchError> {
    let path = path.try_into().map_err(|_| Error::<T>::PathError)?;
    let amount_out_min = amount_out_min.map(Self::convert_hpb_to_coin_balance).transpose()?;
    let amount_out = Self::do_swap_exact_tokens_for_tokens(
      sender,
      path,
      Self::convert_hpb_to_coin_balance(amount_in)?,
      amount_out_min,
      send_to,
    )?;
    Ok(amount_out.into())
  }

  fn swap_tokens_for_exact_tokens(
    sender: T::AccountId,
    path: Vec<Coin>,
    amount_out: T::HigherPrecisionBalance,
    amount_in_max: Option<T::HigherPrecisionBalance>,
    send_to: T::AccountId,
  ) -> Result<T::HigherPrecisionBalance, DispatchError> {
    let path = path.try_into().map_err(|_| Error::<T>::PathError)?;
    let amount_in_max = amount_in_max.map(Self::convert_hpb_to_coin_balance).transpose()?;
    let amount_in = Self::do_swap_tokens_for_exact_tokens(
      sender,
      path,
      Self::convert_hpb_to_coin_balance(amount_out)?,
      amount_in_max,
      send_to,
    )?;
    Ok(amount_in.into())
  }
}

sp_api::decl_runtime_apis! {
  /// This runtime api allows people to query the size of the liquidity pools
  /// and quote prices for swaps.
  pub trait DexApi {
    /// Provides a quote for [`Pallet::swap_tokens_for_exact_tokens`].
    ///
    /// Note that the price may have changed by the time the transaction is executed.
    /// (Use `amount_in_max` to control slippage.)
    fn quote_price_tokens_for_exact_tokens(
      coin1: Coin,
      coin2: Coin,
      amount: SubstrateAmount,
      include_fee: bool
    ) -> Option<SubstrateAmount>;

    /// Provides a quote for [`Pallet::swap_exact_tokens_for_tokens`].
    ///
    /// Note that the price may have changed by the time the transaction is executed.
    /// (Use `amount_out_min` to control slippage.)
    fn quote_price_exact_tokens_for_tokens(
      coin1: Coin,
      coin2: Coin,
      amount: SubstrateAmount,
      include_fee: bool
    ) -> Option<SubstrateAmount>;

    /// Returns the size of the liquidity pool for the given coin pair.
    fn get_reserves(coin1: Coin, coin2: Coin) -> Option<(SubstrateAmount, SubstrateAmount)>;
  }
}

sp_core::generate_feature_enabled_macro!(
  runtime_benchmarks_enabled,
  feature = "runtime-benchmarks",
  $
);
