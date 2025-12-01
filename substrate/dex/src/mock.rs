//! Test environment for the DEX pallet.

use borsh::BorshDeserialize;

use frame_support::{sp_runtime::BuildStorage, derive_impl, construct_runtime};

use serai_coins_pallet::{CoinsInstance, LiquidityTokensInstance};

use crate as dex;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Timestamp: pallet_timestamp,
    Core: serai_core_pallet,
    Coins: serai_coins_pallet::<CoinsInstance>,
    LiquidityTokens: serai_coins_pallet::<LiquidityTokensInstance>,
    Dex: dex,
  }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
  type AccountId = sp_core::sr25519::Public;
  type Lookup = frame_support::sp_runtime::traits::IdentityLookup<Self::AccountId>;
  type Block = frame_system::mocking::MockBlock<Test>;
}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Test {}

impl serai_core_pallet::Config for Test {}

impl serai_coins_pallet::Config<CoinsInstance> for Test {
  type AllowMint = serai_coins_pallet::AlwaysAllowMint;
}

impl serai_coins_pallet::Config<LiquidityTokensInstance> for Test {
  type AllowMint = serai_coins_pallet::AlwaysAllowMint;
}

impl crate::Config for Test {}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
  let mut storage = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();

  serai_coins_pallet::GenesisConfig::<Test, CoinsInstance> {
    accounts: vec![],
    _instance: Default::default(),
  }
  .assimilate_storage(&mut storage)
  .unwrap();
  serai_coins_pallet::GenesisConfig::<Test, LiquidityTokensInstance> {
    accounts: vec![],
    _instance: Default::default(),
  }
  .assimilate_storage(&mut storage)
  .unwrap();

  storage.into()
}
