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
  construct_runtime,
  traits::{ConstU32, ConstU64},
};

use sp_core::{H256, sr25519::Public};
use sp_runtime::{
  traits::{BlakeTwo256, IdentityLookup},
  BuildStorage,
};

use serai_primitives::{Coin, Balance, Amount, system_address};

pub use coins_pallet as coins;
pub use liquidity_tokens_pallet as liquidity_tokens;

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    CoinsPallet: coins,
    LiquidityTokens: liquidity_tokens,
    Dex: dex,
  }
);

impl frame_system::Config for Test {
  type BaseCallFilter = frame_support::traits::Everything;
  type BlockWeights = ();
  type BlockLength = ();
  type RuntimeOrigin = RuntimeOrigin;
  type RuntimeCall = RuntimeCall;
  type Nonce = u64;
  type Hash = H256;
  type Hashing = BlakeTwo256;
  type AccountId = Public;
  type Lookup = IdentityLookup<Self::AccountId>;
  type Block = Block;
  type RuntimeEvent = RuntimeEvent;
  type BlockHashCount = ConstU64<250>;
  type DbWeight = ();
  type Version = ();
  type PalletInfo = PalletInfo;
  type AccountData = ();
  type OnNewAccount = ();
  type OnKilledAccount = ();
  type SystemWeightInfo = ();
  type SS58Prefix = ();
  type OnSetCode = ();
  type MaxConsumers = ConstU32<16>;
}

impl coins::Config for Test {
  type RuntimeEvent = RuntimeEvent;
}

impl liquidity_tokens::Config for Test {
  type RuntimeEvent = RuntimeEvent;
}

pub struct CoinConverter;
impl MultiCoinIdConverter<Coin, Coin> for CoinConverter {
  /// Returns the MultiCoinId representing the native currency of the chain.
  fn get_native() -> Coin {
    Coin::Serai
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

impl Config for Test {
  type RuntimeEvent = RuntimeEvent;
  type Currency = CoinsPallet;
  type CoinBalance = u64;
  type CoinId = Coin;
  type PoolCoinId = u32;
  type Coins = CoinsPallet;
  type PoolCoins = LiquidityTokens;
  type WeightInfo = ();
  type LPFee = ConstU32<3>; // means 0.3%
  type MaxSwapPathLength = ConstU32<4>;
  // 100 is good enough when the main currency has 12 decimals.
  type MintMinLiquidity = ConstU64<100>;

  type Balance = u64;
  type HigherPrecisionBalance = u128;

  type MultiCoinId = Coin;
  type MultiCoinIdConverter = CoinConverter;

  #[cfg(feature = "runtime-benchmarks")]
  type BenchmarkHelper = ();
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
  }
  .assimilate_storage(&mut t)
  .unwrap();

  let mut ext = sp_io::TestExternalities::new(t);
  ext.execute_with(|| System::set_block_number(1));
  ext
}
