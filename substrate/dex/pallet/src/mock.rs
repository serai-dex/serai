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

//! Test environment for Dex pallet.

use super::*;
use crate as dex;

use frame_support::{
  construct_runtime, derive_impl,
  traits::{ConstU16, ConstU32, ConstU64},
};

use sp_core::sr25519::Public;
use sp_runtime::{traits::IdentityLookup, BuildStorage};

use serai_primitives::{Coin, Balance, Amount, system_address};

pub use coins_pallet as coins;

type Block = frame_system::mocking::MockBlock<Test>;

pub const MEDIAN_PRICE_WINDOW_LENGTH: u16 = 10;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    CoinsPallet: coins,
    LiquidityTokens: coins::<Instance1>::{Pallet, Call, Storage, Event<T>},
    Dex: dex,
  }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
  type AccountId = Public;
  type Lookup = IdentityLookup<Self::AccountId>;
  type Block = Block;
}

impl coins::Config for Test {
  type AllowMint = ();
}

impl coins::Config<coins::Instance1> for Test {
  type AllowMint = ();
}

impl Config for Test {
  type WeightInfo = ();
  type LPFee = ConstU32<3>; // means 0.3%
  type MaxSwapPathLength = ConstU32<4>;

  type MedianPriceWindowLength = ConstU16<{ MEDIAN_PRICE_WINDOW_LENGTH }>;

  // 100 is good enough when the main currency has 12 decimals.
  type MintMinLiquidity = ConstU64<100>;
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
  let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();

  let accounts: Vec<Public> = vec![
    system_address(b"account1").into(),
    system_address(b"account2").into(),
    system_address(b"account3").into(),
    system_address(b"account4").into(),
  ];
  coins::GenesisConfig::<Test> {
    accounts: accounts
      .into_iter()
      .map(|a| (a, Balance { coin: Coin::Serai, amount: Amount(1 << 60) }))
      .collect(),
    _ignore: Default::default(),
  }
  .assimilate_storage(&mut t)
  .unwrap();

  let mut ext = sp_io::TestExternalities::new(t);
  ext.execute_with(|| System::set_block_number(1));
  ext
}
