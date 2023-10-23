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

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::DispatchError;
use frame_support::traits::tokens::{Balance, AssetId};

use serai_primitives::Coin;

/// Stores the lp_token asset id a particular pool has been assigned.
#[derive(Decode, Encode, Default, PartialEq, Eq, MaxEncodedLen, TypeInfo)]
pub struct PoolInfo<PoolAssetId> {
  /// Liquidity pool asset
  pub lp_token: PoolAssetId,
}

/// A trait that converts between a MultiAssetId and either the native currency or an AssetId.
pub trait MultiAssetIdConverter<MultiAssetId, AssetId> {
  /// Returns the MultiAssetId representing the native currency of the chain.
  fn get_native() -> MultiAssetId;

  /// Returns true if the given MultiAssetId is the native currency.
  fn is_native(asset: &MultiAssetId) -> bool;

  /// If it's not native, returns the AssetId for the given MultiAssetId.
  fn try_convert(asset: &MultiAssetId) -> MultiAssetIdConversionResult<MultiAssetId, AssetId>;
}

/// Result of `MultiAssetIdConverter::try_convert`.
#[cfg_attr(feature = "std", derive(PartialEq, Debug))]
pub enum MultiAssetIdConversionResult<MultiAssetId, AssetId> {
  /// Input asset is successfully converted. Means that converted asset is supported.
  Converted(AssetId),
  /// Means that input asset is the chain's native asset, if it has one, so no conversion (see
  /// `MultiAssetIdConverter::get_native`).
  Native,
  /// Means input asset is not supported for pool.
  Unsupported(MultiAssetId),
}

/// Benchmark Helper
#[cfg(feature = "runtime-benchmarks")]
pub trait BenchmarkHelper<AssetId, MultiAssetId> {
  /// Returns an `AssetId` from a given integer.
  fn asset_id(asset_id: u32) -> AssetId;

  /// Returns a `MultiAssetId` from a given integer.
  fn multiasset_id(asset_id: u32) -> MultiAssetId;
}

#[cfg(feature = "runtime-benchmarks")]
impl<AssetId, MultiAssetId> BenchmarkHelper<AssetId, MultiAssetId> for ()
where
  AssetId: From<u32>,
  MultiAssetId: From<u32>,
{
  fn asset_id(asset_id: u32) -> AssetId {
    asset_id.into()
  }

  fn multiasset_id(asset_id: u32) -> MultiAssetId {
    asset_id.into()
  }
}

/// Trait for providing methods to swap between the various asset classes.
pub trait Swap<AccountId, Balance, MultiAssetId> {
  /// Swap exactly `amount_in` of asset `path[0]` for asset `path[1]`.
  /// If an `amount_out_min` is specified, it will return an error if it is unable to acquire
  /// the amount desired.
  ///
  /// Withdraws the `path[0]` asset from `sender`, deposits the `path[1]` asset to `send_to`,
  ///
  /// If successful, returns the amount of `path[1]` acquired for the `amount_in`.
  fn swap_exact_tokens_for_tokens(
    sender: AccountId,
    path: Vec<MultiAssetId>,
    amount_in: Balance,
    amount_out_min: Option<Balance>,
    send_to: AccountId,
  ) -> Result<Balance, DispatchError>;

  /// Take the `path[0]` asset and swap some amount for `amount_out` of the `path[1]`. If an
  /// `amount_in_max` is specified, it will return an error if acquiring `amount_out` would be
  /// too costly.
  ///
  /// Withdraws `path[0]` asset from `sender`, deposits `path[1]` asset to `send_to`,
  ///
  /// If successful returns the amount of the `path[0]` taken to provide `path[1]`.
  fn swap_tokens_for_exact_tokens(
    sender: AccountId,
    path: Vec<MultiAssetId>,
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
  /// TODO: make sure of coin precision here?
  fn minimum_balance() -> Self::Balance;

  /// Transfers the given `amount` from `from` to `to`.
  fn transfer(
    from: &AccountId,
    to: &AccountId,
    amount: Self::Balance,
  ) -> Result<Self::Balance, DispatchError>;
}

/// External coin trait for Dex pallet.
pub trait Assets<AccountId>: Sized {
  /// Balance of an Account.
  type Balance: Balance;

  /// Asset identifier.
  type AssetId: AssetId;

  /// Returns the balance of an account.
  fn balance(asset: Self::AssetId, of: &AccountId) -> Self::Balance;

  /// Returns the minimum allowed balance of an account
  /// TODO: make sure of coin precision here?
  fn minimum_balance(asset: Self::AssetId) -> Self::Balance;

  /// Transfers the given `amount` from `from` to `to`.
  fn transfer(
    asset: Self::AssetId,
    from: &AccountId,
    to: &AccountId,
    amount: Self::Balance,
  ) -> Result<Self::Balance, DispatchError>;
}

/// Liquidity tokens trait for Dex pallet.
pub trait LiquidityTokens<AccountId>: Sized {
  /// Amount type.
  type Balance: Balance;

  /// Asset identifier.
  type AssetId: AssetId;

  /// Returns the `token` balance of and account.
  fn balance(token: Self::AssetId, of: &AccountId) -> Self::Balance;

  /// Mints `amount` to `to`.
  fn mint_into(
    token: Self::AssetId,
    to: &AccountId,
    amount: Self::Balance,
  ) -> Result<Self::Balance, DispatchError>;

  /// Burns `amount` from `from`.
  fn burn_from(
    token: Self::AssetId,
    from: &AccountId,
    amount: Self::Balance,
  ) -> Result<Self::Balance, DispatchError>;

  /// Returns total supply for `token`.
  fn total_issuance(token: Self::AssetId) -> Self::Balance;

	/// Returns an iterator of the collections in existence.
	fn asset_ids() -> Vec<Self::AssetId>;
}

pub struct CoinConverter;
impl MultiAssetIdConverter<Coin, Coin> for CoinConverter {
  /// Returns the MultiAssetId representing the native currency of the chain.
  fn get_native() -> Coin {
    Coin::Serai
  }

  /// Returns true if the given MultiAssetId is the native currency.
  fn is_native(coin: &Coin) -> bool {
    coin.is_native()
  }

  /// If it's not native, returns the AssetId for the given MultiAssetId.
  fn try_convert(coin: &Coin) -> MultiAssetIdConversionResult<Coin, Coin> {
    if coin.is_native() {
      MultiAssetIdConversionResult::Native
    } else {
      MultiAssetIdConversionResult::Converted(*coin)
    }
  }
}
