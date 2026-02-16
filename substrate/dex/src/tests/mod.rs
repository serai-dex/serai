#![expect(clippy::as_conversions, clippy::same_name_method)]

use sp_core::{Pair as _, sr25519::Pair};
use frame_support::{sp_runtime::DispatchError, weights::Weight, derive_impl, construct_runtime};

use serai_abi::{
  primitives::{coin::*, balance::*, address::*},
  TransactionContext as _, Event,
};

use serai_coins_pallet::{self as coins, CoinsInstance, LiquidityTokensInstance};

use crate as dex;

mod add_liquidity;
mod transfer_liquidity;
mod remove_liquidity;
mod swap;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Timestamp: pallet_timestamp,
    Core: serai_core_pallet,
    Coins: coins::<CoinsInstance>,
    LiquidityTokens: coins::<LiquidityTokensInstance>,
    Dex: dex,
  }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
  type AccountId = SeraiAddress;
  type Lookup = frame_support::sp_runtime::traits::IdentityLookup<Self::AccountId>;
  type Block = frame_system::mocking::MockBlock<Test>;
  type BlockLength = serai_core_pallet::Limits;
  type BlockWeights = serai_core_pallet::Limits;
}

impl From<serai_abi::Call> for RuntimeCall {
  fn from(_call: serai_abi::Call) -> Self {
    unimplemented!();
  }
}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Test {}

impl serai_core_pallet::Config for Test {
  const PROTOCOL_ID: [u8; 32] = [0; 32];
  const SIGNATURE_VERIFICATION_WEIGHT: Weight = Weight::zero();
  type PreInherents = ();
}

impl serai_coins_pallet::Config<CoinsInstance> for Test {
  type AllowMint = serai_coins_pallet::AlwaysAllowMint;
  type Weights = ();
}
impl serai_coins_pallet::Config<LiquidityTokensInstance> for Test {
  type AllowMint = serai_coins_pallet::AlwaysAllowMint;
  type Weights = ();
}

impl crate::Config for Test {
  type Weights = ();
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
  let mut externalities = sp_io::TestExternalities::new_empty();
  externalities.execute_with(|| {
    let system = frame_system::GenesisConfig::<Test>::default();
    let coins = serai_coins_pallet::GenesisConfig::<Test, CoinsInstance> {
      accounts: vec![],
      _instance: Default::default(),
    };
    let liquidity_tokens = serai_coins_pallet::GenesisConfig::<Test, LiquidityTokensInstance> {
      accounts: vec![],
      _instance: Default::default(),
    };
    let dex = crate::GenesisConfig::<Test> {
      fees: ExternalCoin::all()
        .map(|coin| (coin, if coin == ExternalCoin::Monero { 100 } else { 0 }))
        .collect(),
      _config: Default::default(),
    };
    Core::genesis(&RuntimeGenesisConfig { system, coins, liquidity_tokens, dex });
  });
  externalities
}
