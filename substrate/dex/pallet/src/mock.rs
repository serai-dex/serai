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

//! Test environment for Asset Conversion pallet.

use super::*;
use crate as dex;

use frame_support::{
  construct_runtime, ord_parameter_types, parameter_types,
  traits::{ConstU32, ConstU64, ConstU8},
  weights::IdentityFee,
  PalletId,
};

use sp_arithmetic::Permill;
use sp_core::{H256, sr25519::Public};
use sp_runtime::{
  traits::{BlakeTwo256, IdentityLookup},
  BuildStorage,
};

use serai_primitives::{Coin, Balance, Amount, system_address};

pub use coins_pallet as coins;
pub use liquidity_tokens_pallet as liquidity_tokens;
pub use pallet_transaction_payment as transaction_payment;

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    TransactionPayment: transaction_payment,
    Coins: coins,
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

impl transaction_payment::Config for Test {
  type RuntimeEvent = RuntimeEvent;
  type OnChargeTransaction = Coins;
  type OperationalFeeMultiplier = ConstU8<5>;
  type WeightToFee = IdentityFee<u64>;
  type LengthToFee = IdentityFee<u64>;
  type FeeMultiplierUpdate = ();
}

impl coins::Config for Test {
  type RuntimeEvent = RuntimeEvent;
}

impl liquidity_tokens::Config for Test {
  type RuntimeEvent = RuntimeEvent;
}

parameter_types! {
  pub const AssetConversionPalletId: PalletId = PalletId(*b"py/ascon");
  pub storage AllowMultiAssetPools: bool = true;
  // should be non-zero if AllowMultiAssetPools is true, otherwise can be zero
  pub storage LiquidityWithdrawalFee: Permill = Permill::from_percent(0);
}

ord_parameter_types! {
  pub const AssetConversionOrigin: Public = Public::from(system_address(b"py/ascon"));
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

impl Config for Test {
  type RuntimeEvent = RuntimeEvent;
  type Currency = Coins;
  type AssetBalance = u64;
  type AssetId = Coin;
  type PoolAssetId = u32;
  type Assets = Coins;
  type PoolAssets = LiquidityTokens;
  type PalletId = AssetConversionPalletId;
  type WeightInfo = ();
  type LPFee = ConstU32<3>; // means 0.3%
  type PoolSetupFee = ConstU64<0>; // should be more or equal to the existential deposit
  type PoolSetupFeeReceiver = AssetConversionOrigin;
  type LiquidityWithdrawalFee = LiquidityWithdrawalFee;
  type AllowMultiAssetPools = AllowMultiAssetPools;
  type MaxSwapPathLength = ConstU32<4>;
  // 100 is good enough when the main currency has 12 decimals.
  type MintMinLiquidity = ConstU64<100>;

  type Balance = u64;
  type HigherPrecisionBalance = u128;

  type MultiAssetId = Coin;
  type MultiAssetIdConverter = CoinConverter;

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
