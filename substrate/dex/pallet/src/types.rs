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

use super::*;

use codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;

/// Stores the lp_token coin id a particular pool has been assigned.
#[derive(Decode, Encode, Default, PartialEq, Eq, MaxEncodedLen, TypeInfo)]
pub struct PoolInfo<PoolCoinId> {
  /// Liquidity pool coin
  pub lp_token: PoolCoinId,
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
