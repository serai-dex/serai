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
use frame_support::traits::{DefensiveOption, Incrementable};

#[cfg(feature = "runtime-benchmarks")]
mod benchmarking;

pub mod weights;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod mock;

use codec::Codec;
use frame_support::{
  ensure,
  traits::tokens::{AssetId as CoinId, Balance},
};
use frame_system::{
  ensure_signed,
  pallet_prelude::{BlockNumberFor, OriginFor},
};
pub use pallet::*;
use sp_arithmetic::traits::Unsigned;
use sp_runtime::{
  traits::{
    CheckedAdd, CheckedDiv, CheckedMul, CheckedSub, Ensure, MaybeDisplay, TrailingZeroInput,
  },
  DispatchError,
};
use sp_std::prelude::*;
use dex_primitives::*;
pub use weights::WeightInfo;

#[frame_support::pallet]
pub mod pallet {
  use super::*;
  use frame_support::{pallet_prelude::*, BoundedBTreeSet};
  use sp_runtime::{
    traits::{IntegerSquareRoot, One, Zero},
    Saturating,
  };

  /// Pool ID.
  ///
  /// The pool's `AccountId` is derived from this type. Any changes to the type may necessitate a
  /// migration.
  pub type PoolIdOf<T> = (<T as Config>::MultiCoinId, <T as Config>::MultiCoinId);

  #[pallet::pallet]
  pub struct Pallet<T>(_);

  #[pallet::config]
  pub trait Config: frame_system::Config {
    /// Overarching event type.
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

    /// Currency type that this works on.
    type Currency: Currency<Self::AccountId, Balance = Self::Balance>;

    /// The `Currency::Balance` type of the native currency.
    type Balance: Balance;

    /// The type used to describe the amount of fractions converted into coins.
    type CoinBalance: Balance;

    /// A type used for conversions between `Balance` and `CoinBalance`.
    type HigherPrecisionBalance: IntegerSquareRoot
      + One
      + Ensure
      + Unsigned
      + From<u32>
      + From<Self::CoinBalance>
      + From<Self::Balance>
      + TryInto<Self::CoinBalance>
      + TryInto<Self::Balance>;

    /// Identifier for the class of non-native coin.
    /// Note: A `From<u32>` bound here would prevent `MultiLocation` from being used as an
    /// `CoinId`.
    type CoinId: frame_support::Serialize + sp_runtime::DeserializeOwned + CoinId;

    /// Type that identifies either the native currency or a token class from `Coins`.
    /// `Ord` is added because of `get_pool_id`.
    ///
    /// The pool's `AccountId` is derived from this type. Any changes to the type may
    /// necessitate a migration.
    type MultiCoinId: Ord + CoinId + From<Self::CoinId>;

    /// Type to convert an `CoinId` into `MultiCoinId`.
    type MultiCoinIdConverter: MultiCoinIdConverter<Self::MultiCoinId, Self::CoinId>;

    /// `CoinId` to address the lp tokens by.
    type PoolCoinId: CoinId + PartialOrd + Incrementable + From<u32>;

    /// Registry for the coins.
    type Coins: Coins<Self::AccountId, CoinId = Self::CoinId, Balance = Self::CoinBalance>;

    /// Registry for the lp tokens. Ideally only this pallet should have create permissions on
    /// the coins.
    type PoolCoins: LiquidityTokens<
      Self::AccountId,
      CoinId = Self::PoolCoinId,
      Balance = Self::CoinBalance,
    >;

    /// A % the liquidity providers will take of every swap. Represents 10ths of a percent.
    #[pallet::constant]
    type LPFee: Get<u32>;

    /// The minimum LP token amount that could be minted. Ameliorates rounding errors.
    #[pallet::constant]
    type MintMinLiquidity: Get<Self::CoinBalance>;

    /// The max number of hops in a swap.
    #[pallet::constant]
    type MaxSwapPathLength: Get<u32>;

    /// Weight information for extrinsics in this pallet.
    type WeightInfo: WeightInfo;

    /// The benchmarks need a way to create coin ids from u32s.
    #[cfg(feature = "runtime-benchmarks")]
    type BenchmarkHelper: BenchmarkHelper<Self::CoinId, Self::MultiCoinId>;
  }

  /// Map from `PoolCoinId` to `PoolInfo`. This establishes whether a pool has been officially
  /// created rather than people sending tokens directly to a pool's public account.
  #[pallet::storage]
  pub type Pools<T: Config> =
    StorageMap<_, Blake2_128Concat, PoolIdOf<T>, PoolInfo<T::PoolCoinId>, OptionQuery>;

  /// Stores the `PoolCoinId` that is going to be used for the next lp token.
  /// This gets incremented whenever a new lp pool is created.
  #[pallet::storage]
  pub type NextPoolCoinId<T: Config> = StorageValue<_, T::PoolCoinId, OptionQuery>;

  // Pallet's events.
  #[pallet::event]
  #[pallet::generate_deposit(pub(super) fn deposit_event)]
  pub enum Event<T: Config> {
    /// A successful call of the `CretaPool` extrinsic will create this event.
    PoolCreated {
      /// The pool id associated with the pool. Note that the order of the coins may not be
      /// the same as the order specified in the create pool extrinsic.
      pool_id: PoolIdOf<T>,
      /// The account ID of the pool.
      pool_account: T::AccountId,
      /// The id of the liquidity tokens that will be minted when coins are added to this
      /// pool.
      lp_token: T::PoolCoinId,
    },

    /// A successful call of the `AddLiquidity` extrinsic will create this event.
    LiquidityAdded {
      /// The account that the liquidity was taken from.
      who: T::AccountId,
      /// The account that the liquidity tokens were minted to.
      mint_to: T::AccountId,
      /// The pool id of the pool that the liquidity was added to.
      pool_id: PoolIdOf<T>,
      /// The amount of the first coin that was added to the pool.
      amount1_provided: T::CoinBalance,
      /// The amount of the second coin that was added to the pool.
      amount2_provided: T::CoinBalance,
      /// The id of the lp token that was minted.
      lp_token: T::PoolCoinId,
      /// The amount of lp tokens that were minted of that id.
      lp_token_minted: T::CoinBalance,
    },

    /// A successful call of the `RemoveLiquidity` extrinsic will create this event.
    LiquidityRemoved {
      /// The account that the liquidity tokens were burned from.
      who: T::AccountId,
      /// The account that the coins were transferred to.
      withdraw_to: T::AccountId,
      /// The pool id that the liquidity was removed from.
      pool_id: PoolIdOf<T>,
      /// The amount of the first coin that was removed from the pool.
      amount1: T::CoinBalance,
      /// The amount of the second coin that was removed from the pool.
      amount2: T::CoinBalance,
      /// The id of the lp token that was burned.
      lp_token: T::PoolCoinId,
      /// The amount of lp tokens that were burned of that id.
      lp_token_burned: T::CoinBalance,
    },
    /// Coins have been converted from one to another. Both `SwapExactTokenForToken`
    /// and `SwapTokenForExactToken` will generate this event.
    SwapExecuted {
      /// Which account was the instigator of the swap.
      who: T::AccountId,
      /// The account that the coins were transferred to.
      send_to: T::AccountId,
      /// The route of coin ids that the swap went through.
      /// E.g. A -> Dot -> B
      path: BoundedVec<T::MultiCoinId, T::MaxSwapPathLength>,
      /// The amount of the first coin that was swapped.
      amount_in: T::CoinBalance,
      /// The amount of the second coin that was received.
      amount_out: T::CoinBalance,
    },
    /// An amount has been transferred from one account to another.
    Transfer {
      /// The account that the coins were transferred from.
      from: T::AccountId,
      /// The account that the coins were transferred to.
      to: T::AccountId,
      /// The coin that was transferred.
      coin: T::MultiCoinId,
      /// The amount of the coin that was transferred.
      amount: T::CoinBalance,
    },
  }

  #[pallet::genesis_config]
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
  pub struct GenesisConfig<T: Config> {
    /// Pools to create at launch.
    pub pools: Vec<T::CoinId>,
  }

  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      GenesisConfig { pools: Default::default() }
    }
  }

  #[pallet::genesis_build]
  impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
    fn build(&self) {
      for coin in &self.pools {
        Pallet::<T>::create_pool(coin.clone().into()).unwrap();
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
    pub(crate) fn create_pool(coin2: T::MultiCoinId) -> DispatchResult {
      let coin1 = T::MultiCoinIdConverter::get_native();
      ensure!(coin1 != coin2, Error::<T>::EqualCoins);

      // prepare pool_id
      let pool_id = Self::get_pool_id(coin1, coin2);
      ensure!(!Pools::<T>::contains_key(&pool_id), Error::<T>::PoolExists);

      let pool_account = Self::get_pool_account(&pool_id);
      frame_system::Pallet::<T>::inc_providers(&pool_account);

      let lp_token = NextPoolCoinId::<T>::get()
        .or(T::PoolCoinId::initial_value())
        .ok_or(Error::<T>::IncorrectPoolCoinId)?;
      let next_lp_token_id = lp_token.increment().ok_or(Error::<T>::IncorrectPoolCoinId)?;
      NextPoolCoinId::<T>::set(Some(next_lp_token_id));

      let pool_info = PoolInfo { lp_token: lp_token.clone() };
      Pools::<T>::insert(pool_id.clone(), pool_info);

      Self::deposit_event(Event::PoolCreated { pool_id, pool_account, lp_token });

      Ok(())
    }
  }

  /// Pallet's callable functions.
  // TODO: For all of these calls, limit one of these to always be Coin::Serai
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
      coin1: T::MultiCoinId,
      coin2: T::MultiCoinId,
      amount1_desired: T::CoinBalance,
      amount2_desired: T::CoinBalance,
      amount1_min: T::CoinBalance,
      amount2_min: T::CoinBalance,
      mint_to: T::AccountId,
    ) -> DispatchResult {
      let sender = ensure_signed(origin)?;

      let pool_id = Self::get_pool_id(coin1.clone(), coin2.clone());
      // swap params if needed
      let (amount1_desired, amount2_desired, amount1_min, amount2_min) = if pool_id.0 == coin1 {
        (amount1_desired, amount2_desired, amount1_min, amount2_min)
      } else {
        (amount2_desired, amount1_desired, amount2_min, amount1_min)
      };
      ensure!(
        amount1_desired > Zero::zero() && amount2_desired > Zero::zero(),
        Error::<T>::WrongDesiredAmount
      );

      let maybe_pool = Pools::<T>::get(&pool_id);
      let pool = maybe_pool.as_ref().ok_or(Error::<T>::PoolNotFound)?;
      let pool_account = Self::get_pool_account(&pool_id);

      let (coin1, coin2) = &pool_id;
      let reserve1 = Self::get_balance(&pool_account, coin1)?;
      let reserve2 = Self::get_balance(&pool_account, coin2)?;

      let amount1: T::CoinBalance;
      let amount2: T::CoinBalance;
      if reserve1.is_zero() || reserve2.is_zero() {
        amount1 = amount1_desired;
        amount2 = amount2_desired;
      } else {
        let amount2_optimal = Self::quote(&amount1_desired, &reserve1, &reserve2)?;

        if amount2_optimal <= amount2_desired {
          ensure!(amount2_optimal >= amount2_min, Error::<T>::CoinTwoDepositDidNotMeetMinimum);
          amount1 = amount1_desired;
          amount2 = amount2_optimal;
        } else {
          let amount1_optimal = Self::quote(&amount2_desired, &reserve2, &reserve1)?;
          ensure!(amount1_optimal <= amount1_desired, Error::<T>::OptimalAmountLessThanDesired);
          ensure!(amount1_optimal >= amount1_min, Error::<T>::CoinOneDepositDidNotMeetMinimum);
          amount1 = amount1_optimal;
          amount2 = amount2_desired;
        }
      }

      Self::validate_minimal_amount(amount1.saturating_add(reserve1), coin1)
        .map_err(|_| Error::<T>::AmountOneLessThanMinimal)?;
      Self::validate_minimal_amount(amount2.saturating_add(reserve2), coin2)
        .map_err(|_| Error::<T>::AmountTwoLessThanMinimal)?;

      Self::transfer(coin1, &sender, &pool_account, amount1)?;
      Self::transfer(coin2, &sender, &pool_account, amount2)?;

      let total_supply = T::PoolCoins::total_issuance(pool.lp_token.clone());

      let lp_token_amount: T::CoinBalance;
      if total_supply.is_zero() {
        lp_token_amount = Self::calc_lp_amount_for_zero_supply(&amount1, &amount2)?;
        T::PoolCoins::mint_into(pool.lp_token.clone(), &pool_account, T::MintMinLiquidity::get())?;
      } else {
        let side1 = Self::mul_div(&amount1, &total_supply, &reserve1)?;
        let side2 = Self::mul_div(&amount2, &total_supply, &reserve2)?;
        lp_token_amount = side1.min(side2);
      }

      ensure!(
        lp_token_amount > T::MintMinLiquidity::get(),
        Error::<T>::InsufficientLiquidityMinted
      );

      T::PoolCoins::mint_into(pool.lp_token.clone(), &mint_to, lp_token_amount)?;

      Self::deposit_event(Event::LiquidityAdded {
        who: sender,
        mint_to,
        pool_id,
        amount1_provided: amount1,
        amount2_provided: amount2,
        lp_token: pool.lp_token.clone(),
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
      coin1: T::MultiCoinId,
      coin2: T::MultiCoinId,
      lp_token_burn: T::CoinBalance,
      amount1_min_receive: T::CoinBalance,
      amount2_min_receive: T::CoinBalance,
      withdraw_to: T::AccountId,
    ) -> DispatchResult {
      let sender = ensure_signed(origin)?;

      let pool_id = Self::get_pool_id(coin1.clone(), coin2.clone());
      // swap params if needed
      let (amount1_min_receive, amount2_min_receive) = if pool_id.0 == coin1 {
        (amount1_min_receive, amount2_min_receive)
      } else {
        (amount2_min_receive, amount1_min_receive)
      };
      let (coin1, coin2) = pool_id.clone();

      ensure!(lp_token_burn > Zero::zero(), Error::<T>::ZeroLiquidity);

      let maybe_pool = Pools::<T>::get(&pool_id);
      let pool = maybe_pool.as_ref().ok_or(Error::<T>::PoolNotFound)?;

      let pool_account = Self::get_pool_account(&pool_id);
      let reserve1 = Self::get_balance(&pool_account, &coin1)?;
      let reserve2 = Self::get_balance(&pool_account, &coin2)?;

      let total_supply = T::PoolCoins::total_issuance(pool.lp_token.clone());
      let lp_redeem_amount = lp_token_burn;

      let amount1 = Self::mul_div(&lp_redeem_amount, &reserve1, &total_supply)?;
      let amount2 = Self::mul_div(&lp_redeem_amount, &reserve2, &total_supply)?;

      ensure!(
        !amount1.is_zero() && amount1 >= amount1_min_receive,
        Error::<T>::CoinOneWithdrawalDidNotMeetMinimum
      );
      ensure!(
        !amount2.is_zero() && amount2 >= amount2_min_receive,
        Error::<T>::CoinTwoWithdrawalDidNotMeetMinimum
      );
      let reserve1_left = reserve1.saturating_sub(amount1);
      let reserve2_left = reserve2.saturating_sub(amount2);
      Self::validate_minimal_amount(reserve1_left, &coin1)
        .map_err(|_| Error::<T>::ReserveLeftLessThanMinimal)?;
      Self::validate_minimal_amount(reserve2_left, &coin2)
        .map_err(|_| Error::<T>::ReserveLeftLessThanMinimal)?;

      // burn the provided lp token amount that includes the fee
      T::PoolCoins::burn_from(pool.lp_token.clone(), &sender, lp_token_burn)?;

      Self::transfer(&coin1, &pool_account, &withdraw_to, amount1)?;
      Self::transfer(&coin2, &pool_account, &withdraw_to, amount2)?;

      Self::deposit_event(Event::LiquidityRemoved {
        who: sender,
        withdraw_to,
        pool_id,
        amount1,
        amount2,
        lp_token: pool.lp_token.clone(),
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
      path: BoundedVec<T::MultiCoinId, T::MaxSwapPathLength>,
      amount_in: T::CoinBalance,
      amount_out_min: T::CoinBalance,
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
      path: BoundedVec<T::MultiCoinId, T::MaxSwapPathLength>,
      amount_out: T::CoinBalance,
      amount_in_max: T::CoinBalance,
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
      path: BoundedVec<T::MultiCoinId, T::MaxSwapPathLength>,
      amount_in: T::CoinBalance,
      amount_out_min: Option<T::CoinBalance>,
      send_to: T::AccountId,
    ) -> Result<T::CoinBalance, DispatchError> {
      ensure!(amount_in > Zero::zero(), Error::<T>::ZeroAmount);
      if let Some(amount_out_min) = amount_out_min {
        ensure!(amount_out_min > Zero::zero(), Error::<T>::ZeroAmount);
      }

      Self::validate_swap_path(&path)?;

      let amounts = Self::get_amounts_out(&amount_in, &path)?;
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
      path: BoundedVec<T::MultiCoinId, T::MaxSwapPathLength>,
      amount_out: T::CoinBalance,
      amount_in_max: Option<T::CoinBalance>,
      send_to: T::AccountId,
    ) -> Result<T::CoinBalance, DispatchError> {
      ensure!(amount_out > Zero::zero(), Error::<T>::ZeroAmount);
      if let Some(amount_in_max) = amount_in_max {
        ensure!(amount_in_max > Zero::zero(), Error::<T>::ZeroAmount);
      }

      Self::validate_swap_path(&path)?;

      let amounts = Self::get_amounts_in(&amount_out, &path)?;
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
      coin_id: &T::MultiCoinId,
      from: &T::AccountId,
      to: &T::AccountId,
      amount: T::CoinBalance,
    ) -> Result<T::CoinBalance, DispatchError> {
      let result = match T::MultiCoinIdConverter::try_convert(coin_id) {
        MultiCoinIdConversionResult::Converted(coin_id) => {
          T::Coins::transfer(coin_id, from, to, amount)
        }
        MultiCoinIdConversionResult::Native => {
          let amount = Self::convert_coin_balance_to_native_balance(amount)?;
          Ok(Self::convert_native_balance_to_coin_balance(T::Currency::transfer(
            from, to, amount,
          )?)?)
        }
        MultiCoinIdConversionResult::Unsupported(_) => Err(Error::<T>::UnsupportedCoin.into()),
      };

      if result.is_ok() {
        Self::deposit_event(Event::Transfer {
          from: from.clone(),
          to: to.clone(),
          coin: (*coin_id).clone(),
          amount,
        });
      }
      result
    }

    /// Convert a `Balance` type to an `CoinBalance`.
    pub(crate) fn convert_native_balance_to_coin_balance(
      amount: T::Balance,
    ) -> Result<T::CoinBalance, Error<T>> {
      T::HigherPrecisionBalance::from(amount).try_into().map_err(|_| Error::<T>::Overflow)
    }

    /// Convert an `CoinBalance` type to a `Balance`.
    pub(crate) fn convert_coin_balance_to_native_balance(
      amount: T::CoinBalance,
    ) -> Result<T::Balance, Error<T>> {
      T::HigherPrecisionBalance::from(amount).try_into().map_err(|_| Error::<T>::Overflow)
    }

    /// Convert a `HigherPrecisionBalance` type to an `CoinBalance`.
    pub(crate) fn convert_hpb_to_coin_balance(
      amount: T::HigherPrecisionBalance,
    ) -> Result<T::CoinBalance, Error<T>> {
      amount.try_into().map_err(|_| Error::<T>::Overflow)
    }

    /// Swap coins along a `path`, depositing in `send_to`.
    pub(crate) fn do_swap(
      sender: T::AccountId,
      amounts: &Vec<T::CoinBalance>,
      path: BoundedVec<T::MultiCoinId, T::MaxSwapPathLength>,
      send_to: T::AccountId,
    ) -> Result<(), DispatchError> {
      ensure!(amounts.len() > 1, Error::<T>::CorrespondenceError);
      if let Some([coin1, coin2]) = &path.get(0 .. 2) {
        let pool_id = Self::get_pool_id(coin1.clone(), coin2.clone());
        let pool_account = Self::get_pool_account(&pool_id);
        // amounts should always contain a corresponding element to path.
        let first_amount = amounts.first().ok_or(Error::<T>::CorrespondenceError)?;

        Self::transfer(coin1, &sender, &pool_account, *first_amount)?;

        let mut i = 0;
        let path_len = path.len() as u32;
        for coins_pair in path.windows(2) {
          if let [coin1, coin2] = coins_pair {
            let pool_id = Self::get_pool_id(coin1.clone(), coin2.clone());
            let pool_account = Self::get_pool_account(&pool_id);

            let amount_out =
              amounts.get((i + 1) as usize).ok_or(Error::<T>::CorrespondenceError)?;

            let to = if i < path_len - 2 {
              let coin3 = path.get((i + 2) as usize).ok_or(Error::<T>::PathError)?;
              Self::get_pool_account(&Self::get_pool_id(coin2.clone(), coin3.clone()))
            } else {
              send_to.clone()
            };

            let reserve = Self::get_balance(&pool_account, coin2)?;
            let reserve_left = reserve.saturating_sub(*amount_out);
            Self::validate_minimal_amount(reserve_left, coin2)
              .map_err(|_| Error::<T>::ReserveLeftLessThanMinimal)?;

            Self::transfer(coin2, &pool_account, &to, *amount_out)?;
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
    pub fn get_pool_account(pool_id: &PoolIdOf<T>) -> T::AccountId {
      let encoded_pool_id = sp_io::hashing::blake2_256(&Encode::encode(pool_id)[..]);

      Decode::decode(&mut TrailingZeroInput::new(encoded_pool_id.as_ref()))
        .expect("infinite length input; no invalid inputs for type; qed")
    }

    /// Get the `owner`'s balance of `coin`, which could be the chain's native coin or another
    /// fungible. Returns a value in the form of an `CoinBalance`.
    fn get_balance(
      owner: &T::AccountId,
      coin: &T::MultiCoinId,
    ) -> Result<T::CoinBalance, Error<T>> {
      match T::MultiCoinIdConverter::try_convert(coin) {
        MultiCoinIdConversionResult::Converted(coin_id) => {
          Ok(<<T as Config>::Coins>::balance(coin_id, owner))
        }
        MultiCoinIdConversionResult::Native => {
          Self::convert_native_balance_to_coin_balance(<<T as Config>::Currency>::balance(owner))
        }
        MultiCoinIdConversionResult::Unsupported(_) => Err(Error::<T>::UnsupportedCoin),
      }
    }

    /// Returns a pool id constructed from 2 coins.
    /// 1. Native coin should be lower than the other coin ids.
    /// 2. Two native or two non-native coins are compared by their `Ord` implementation.
    ///
    /// We expect deterministic order, so (coin1, coin2) or (coin2, coin1) returns the same
    /// result.
    pub fn get_pool_id(coin1: T::MultiCoinId, coin2: T::MultiCoinId) -> PoolIdOf<T> {
      match (T::MultiCoinIdConverter::is_native(&coin1), T::MultiCoinIdConverter::is_native(&coin2))
      {
        (true, false) => (coin1, coin2),
        (false, true) => (coin2, coin1),
        _ => {
          // else we want to be deterministic based on `Ord` implementation
          if coin1 <= coin2 {
            (coin1, coin2)
          } else {
            (coin2, coin1)
          }
        }
      }
    }

    /// Returns the balance of each coin in the pool.
    /// The tuple result is in the order requested (not necessarily the same as pool order).
    pub fn get_reserves(
      coin1: &T::MultiCoinId,
      coin2: &T::MultiCoinId,
    ) -> Result<(T::CoinBalance, T::CoinBalance), Error<T>> {
      let pool_id = Self::get_pool_id(coin1.clone(), coin2.clone());
      let pool_account = Self::get_pool_account(&pool_id);

      let balance1 = Self::get_balance(&pool_account, coin1)?;
      let balance2 = Self::get_balance(&pool_account, coin2)?;

      if balance1.is_zero() || balance2.is_zero() {
        Err(Error::<T>::PoolNotFound)?;
      }

      Ok((balance1, balance2))
    }

    /// Leading to an amount at the end of a `path`, get the required amounts in.
    pub(crate) fn get_amounts_in(
      amount_out: &T::CoinBalance,
      path: &BoundedVec<T::MultiCoinId, T::MaxSwapPathLength>,
    ) -> Result<Vec<T::CoinBalance>, DispatchError> {
      let mut amounts: Vec<T::CoinBalance> = vec![*amount_out];

      for coins_pair in path.windows(2).rev() {
        if let [coin1, coin2] = coins_pair {
          let (reserve_in, reserve_out) = Self::get_reserves(coin1, coin2)?;
          let prev_amount = amounts.last().expect("Always has at least one element");
          let amount_in = Self::get_amount_in(prev_amount, &reserve_in, &reserve_out)?;
          amounts.push(amount_in);
        }
      }

      amounts.reverse();
      Ok(amounts)
    }

    /// Following an amount into a `path`, get the corresponding amounts out.
    pub(crate) fn get_amounts_out(
      amount_in: &T::CoinBalance,
      path: &BoundedVec<T::MultiCoinId, T::MaxSwapPathLength>,
    ) -> Result<Vec<T::CoinBalance>, DispatchError> {
      let mut amounts: Vec<T::CoinBalance> = vec![*amount_in];

      for coins_pair in path.windows(2) {
        if let [coin1, coin2] = coins_pair {
          let (reserve_in, reserve_out) = Self::get_reserves(coin1, coin2)?;
          let prev_amount = amounts.last().expect("Always has at least one element");
          let amount_out = Self::get_amount_out(prev_amount, &reserve_in, &reserve_out)?;
          amounts.push(amount_out);
        }
      }

      Ok(amounts)
    }

    /// Used by the RPC service to provide current prices.
    pub fn quote_price_exact_tokens_for_tokens(
      coin1: T::MultiCoinId,
      coin2: T::MultiCoinId,
      amount: T::CoinBalance,
      include_fee: bool,
    ) -> Option<T::CoinBalance> {
      let pool_id = Self::get_pool_id(coin1.clone(), coin2.clone());
      let pool_account = Self::get_pool_account(&pool_id);

      let balance1 = Self::get_balance(&pool_account, &coin1).ok()?;
      let balance2 = Self::get_balance(&pool_account, &coin2).ok()?;
      if !balance1.is_zero() {
        if include_fee {
          Self::get_amount_out(&amount, &balance1, &balance2).ok()
        } else {
          Self::quote(&amount, &balance1, &balance2).ok()
        }
      } else {
        None
      }
    }

    /// Used by the RPC service to provide current prices.
    pub fn quote_price_tokens_for_exact_tokens(
      coin1: T::MultiCoinId,
      coin2: T::MultiCoinId,
      amount: T::CoinBalance,
      include_fee: bool,
    ) -> Option<T::CoinBalance> {
      let pool_id = Self::get_pool_id(coin1.clone(), coin2.clone());
      let pool_account = Self::get_pool_account(&pool_id);

      let balance1 = Self::get_balance(&pool_account, &coin1).ok()?;
      let balance2 = Self::get_balance(&pool_account, &coin2).ok()?;
      if !balance1.is_zero() {
        if include_fee {
          Self::get_amount_in(&amount, &balance1, &balance2).ok()
        } else {
          Self::quote(&amount, &balance2, &balance1).ok()
        }
      } else {
        None
      }
    }

    /// Calculates the optimal amount from the reserves.
    pub fn quote(
      amount: &T::CoinBalance,
      reserve1: &T::CoinBalance,
      reserve2: &T::CoinBalance,
    ) -> Result<T::CoinBalance, Error<T>> {
      // amount * reserve2 / reserve1
      Self::mul_div(amount, reserve2, reserve1)
    }

    pub(super) fn calc_lp_amount_for_zero_supply(
      amount1: &T::CoinBalance,
      amount2: &T::CoinBalance,
    ) -> Result<T::CoinBalance, Error<T>> {
      let amount1 = T::HigherPrecisionBalance::from(*amount1);
      let amount2 = T::HigherPrecisionBalance::from(*amount2);

      let result = amount1
        .checked_mul(&amount2)
        .ok_or(Error::<T>::Overflow)?
        .integer_sqrt()
        .checked_sub(&T::MintMinLiquidity::get().into())
        .ok_or(Error::<T>::InsufficientLiquidityMinted)?;

      result.try_into().map_err(|_| Error::<T>::Overflow)
    }

    fn mul_div(
      a: &T::CoinBalance,
      b: &T::CoinBalance,
      c: &T::CoinBalance,
    ) -> Result<T::CoinBalance, Error<T>> {
      let a = T::HigherPrecisionBalance::from(*a);
      let b = T::HigherPrecisionBalance::from(*b);
      let c = T::HigherPrecisionBalance::from(*c);

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
      amount_in: &T::CoinBalance,
      reserve_in: &T::CoinBalance,
      reserve_out: &T::CoinBalance,
    ) -> Result<T::CoinBalance, Error<T>> {
      let amount_in = T::HigherPrecisionBalance::from(*amount_in);
      let reserve_in = T::HigherPrecisionBalance::from(*reserve_in);
      let reserve_out = T::HigherPrecisionBalance::from(*reserve_out);

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
      amount_out: &T::CoinBalance,
      reserve_in: &T::CoinBalance,
      reserve_out: &T::CoinBalance,
    ) -> Result<T::CoinBalance, Error<T>> {
      let amount_out = T::HigherPrecisionBalance::from(*amount_out);
      let reserve_in = T::HigherPrecisionBalance::from(*reserve_in);
      let reserve_out = T::HigherPrecisionBalance::from(*reserve_out);

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
    fn validate_minimal_amount(value: T::CoinBalance, coin: &T::MultiCoinId) -> Result<(), ()> {
      if T::MultiCoinIdConverter::is_native(coin) {
        let ed = T::Currency::minimum_balance();
        ensure!(T::HigherPrecisionBalance::from(value) >= T::HigherPrecisionBalance::from(ed), ());
      } else {
        let MultiCoinIdConversionResult::Converted(coin_id) =
          T::MultiCoinIdConverter::try_convert(coin)
        else {
          return Err(());
        };
        let minimal = T::Coins::minimum_balance(coin_id);
        ensure!(value >= minimal, ());
      }
      Ok(())
    }

    /// Ensure that a path is valid.
    fn validate_swap_path(
      path: &BoundedVec<T::MultiCoinId, T::MaxSwapPathLength>,
    ) -> Result<(), DispatchError> {
      ensure!(path.len() >= 2, Error::<T>::InvalidPath);

      // validate all the pools in the path are unique
      let mut pools = BoundedBTreeSet::<PoolIdOf<T>, T::MaxSwapPathLength>::new();
      for coins_pair in path.windows(2) {
        if let [coin1, coin2] = coins_pair {
          let pool_id = Self::get_pool_id(coin1.clone(), coin2.clone());
          let new_element = pools.try_insert(pool_id).map_err(|_| Error::<T>::Overflow)?;
          if !new_element {
            return Err(Error::<T>::NonUniquePath.into());
          }
        }
      }
      Ok(())
    }

    /// Returns the next pool coin id for benchmark purposes only.
    #[cfg(any(test, feature = "runtime-benchmarks"))]
    pub fn get_next_pool_coin_id() -> T::PoolCoinId {
      NextPoolCoinId::<T>::get()
        .or(T::PoolCoinId::initial_value())
        .expect("Next pool coin ID can not be None")
    }
  }
}

impl<T: Config> Swap<T::AccountId, T::HigherPrecisionBalance, T::MultiCoinId> for Pallet<T> {
  fn swap_exact_tokens_for_tokens(
    sender: T::AccountId,
    path: Vec<T::MultiCoinId>,
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
    path: Vec<T::MultiCoinId>,
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
  pub trait DexApi<Balance, CoinBalance, CoinId> where
    Balance: Codec + MaybeDisplay,
    CoinBalance: frame_support::traits::tokens::Balance,
    CoinId: Codec
  {
    /// Provides a quote for [`Pallet::swap_tokens_for_exact_tokens`].
    ///
    /// Note that the price may have changed by the time the transaction is executed.
    /// (Use `amount_in_max` to control slippage.)
    fn quote_price_tokens_for_exact_tokens(
      coin1: CoinId,
      coin2: CoinId,
      amount: CoinBalance,
      include_fee: bool
    ) -> Option<Balance>;

    /// Provides a quote for [`Pallet::swap_exact_tokens_for_tokens`].
    ///
    /// Note that the price may have changed by the time the transaction is executed.
    /// (Use `amount_out_min` to control slippage.)
    fn quote_price_exact_tokens_for_tokens(
      coin1: CoinId,
      coin2: CoinId,
      amount: CoinBalance,
      include_fee: bool
    ) -> Option<Balance>;

    /// Returns the size of the liquidity pool for the given coin pair.
    fn get_reserves(coin1: CoinId, coin2: CoinId) -> Option<(Balance, Balance)>;
  }
}

sp_core::generate_feature_enabled_macro!(
  runtime_benchmarks_enabled,
  feature = "runtime-benchmarks",
  $
);
