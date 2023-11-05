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

#![cfg_attr(not(feature = "std"), no_std)]

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

use sp_runtime::DispatchError;
use sp_std::vec::Vec;

use frame_support::traits::tokens::{Balance, AssetId as CoinId};

use serai_primitives::Coin;

/// Stores the lp_token coin id a particular pool has been assigned.
#[derive(Decode, Encode, Default, PartialEq, Eq, MaxEncodedLen, TypeInfo)]
pub struct PoolInfo<PoolCoinId> {
  /// Liquidity pool coin
  pub lp_token: PoolCoinId,
}

/// A trait that converts between a MultiCoinId and either the native currency or an CoinId.
pub trait MultiCoinIdConverter<MultiCoinId, CoinId> {
  /// Returns the MultiCoinId representing the native currency of the chain.
  fn get_native() -> MultiCoinId;

  /// Returns true if the given MultiCoinId is the native currency.
  fn is_native(coin: &MultiCoinId) -> bool;

  /// If it's not native, returns the CoinId for the given MultiCoinId.
  fn try_convert(coin: &MultiCoinId) -> MultiCoinIdConversionResult<MultiCoinId, CoinId>;
}

/// Result of `MultiCoinIdConverter::try_convert`.
#[cfg_attr(feature = "std", derive(PartialEq, Debug))]
pub enum MultiCoinIdConversionResult<MultiCoinId, CoinId> {
  /// Input coin is successfully converted. Means that converted coin is supported.
  Converted(CoinId),
  /// Means that input coin is the chain's native coin, if it has one, so no conversion (see
  /// `MultiCoinIdConverter::get_native`).
  Native,
  /// Means input coin is not supported for pool.
  Unsupported(MultiCoinId),
}

/// Benchmark Helper
#[cfg(feature = "runtime-benchmarks")]
pub trait BenchmarkHelper<CoinId, MultiCoinId> {
  /// Returns an `CoinId` from a given integer.
  fn coin_id(coin_id: u32) -> CoinId;
}

#[cfg(feature = "runtime-benchmarks")]
mod runtime_benchmarks {
  use super::*;
  use serai_primitives::COINS;
  impl BenchmarkHelper<Coin, Coin> for () {
    fn coin_id(coin_id: u32) -> Coin {
      // we shift id 1 unit to the left, since id 0 is the native coin.
      COINS[(usize::try_from(coin_id).unwrap() % COINS.len()) + 1]
    }
  }
}

/// Trait for providing methods to swap between the various coin classes.
pub trait Swap<AccountId, Balance, MultiCoinId> {
  /// Swap exactly `amount_in` of coin `path[0]` for coin `path[1]`.
  /// If an `amount_out_min` is specified, it will return an error if it is unable to acquire
  /// the amount desired.
  ///
  /// Withdraws the `path[0]` coin from `sender`, deposits the `path[1]` coin to `send_to`,
  ///
  /// If successful, returns the amount of `path[1]` acquired for the `amount_in`.
  fn swap_exact_tokens_for_tokens(
    sender: AccountId,
    path: Vec<MultiCoinId>,
    amount_in: Balance,
    amount_out_min: Option<Balance>,
    send_to: AccountId,
  ) -> Result<Balance, DispatchError>;

  /// Take the `path[0]` coin and swap some amount for `amount_out` of the `path[1]`. If an
  /// `amount_in_max` is specified, it will return an error if acquiring `amount_out` would be
  /// too costly.
  ///
  /// Withdraws `path[0]` coin from `sender`, deposits `path[1]` coin to `send_to`,
  ///
  /// If successful returns the amount of the `path[0]` taken to provide `path[1]`.
  fn swap_tokens_for_exact_tokens(
    sender: AccountId,
    path: Vec<MultiCoinId>,
    amount_out: Balance,
    amount_in_max: Option<Balance>,
    send_to: AccountId,
  ) -> Result<Balance, DispatchError>;
}

// TODO: Sized should be there?
/// Native coin trait for Dex pallet.
pub trait Currency<AccountId>: Sized {
  /// Balance of an Account.
  type Balance: Balance;

  /// Returns the balance of an account.
  fn balance(of: &AccountId) -> Self::Balance;

  /// Returns the minimum allowed balance of an account
  fn minimum_balance() -> Self::Balance;

  /// Transfers the given `amount` from `from` to `to`.
  fn transfer(
    from: &AccountId,
    to: &AccountId,
    amount: Self::Balance,
  ) -> Result<Self::Balance, DispatchError>;

  /// mints the given `amount` into `to`.
  fn mint(to: &AccountId, amount: Self::Balance) -> Result<Self::Balance, DispatchError>;
}

/// External coin trait for Dex pallet.
pub trait Coins<AccountId>: Sized {
  /// Balance of an Account.
  type Balance: Balance;

  /// Coin identifier.
  type CoinId: CoinId;

  /// Returns the balance of an account.
  fn balance(coin: Self::CoinId, of: &AccountId) -> Self::Balance;

  /// Returns the minimum allowed balance of an account
  fn minimum_balance(coin: Self::CoinId) -> Self::Balance;

  /// Transfers the given `amount` from `from` to `to`.
  fn transfer(
    coin: Self::CoinId,
    from: &AccountId,
    to: &AccountId,
    amount: Self::Balance,
  ) -> Result<Self::Balance, DispatchError>;

  /// mints the given `amount` of `coin` into `to`.
  fn mint(
    coin: Self::CoinId,
    to: &AccountId,
    amount: Self::Balance,
  ) -> Result<Self::Balance, DispatchError>;
}

/// Liquidity tokens trait for Dex pallet.
pub trait LiquidityTokens<AccountId>: Sized {
  /// Amount type.
  type Balance: Balance;

  /// Coin identifier.
  type CoinId: CoinId;

  /// Returns the `token` balance of and account.
  fn balance(token: Self::CoinId, of: &AccountId) -> Self::Balance;

  /// Mints `amount` to `to`.
  fn mint_into(
    token: Self::CoinId,
    to: &AccountId,
    amount: Self::Balance,
  ) -> Result<Self::Balance, DispatchError>;

  /// Burns `amount` from `from`.
  fn burn_from(
    token: Self::CoinId,
    from: &AccountId,
    amount: Self::Balance,
  ) -> Result<Self::Balance, DispatchError>;

  /// Returns total supply for `token`.
  fn total_issuance(token: Self::CoinId) -> Self::Balance;

  /// Returns an iterator of the collections in existence.
  fn coin_ids() -> Vec<Self::CoinId>;
}

pub struct CoinConverter;
impl MultiCoinIdConverter<Coin, Coin> for CoinConverter {
  /// Returns the MultiCoinId representing the native currency of the chain.
  fn get_native() -> Coin {
    Coin::native()
  }

  /// Returns true if the given MultiCoinId is the native currency.
  fn is_native(coin: &Coin) -> bool {
    coin.is_native()
  }

  /// If it's not native, returns the CoinId for the given MultiCoinId.
  fn try_convert(coin: &Coin) -> MultiCoinIdConversionResult<Coin, Coin> {
    if coin.is_native() {
      MultiCoinIdConversionResult::Native
    } else {
      MultiCoinIdConversionResult::Converted(*coin)
    }
  }
}
