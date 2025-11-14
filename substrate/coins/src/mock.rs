//! Test environment for Coins pallet.

use borsh::BorshDeserialize;

use frame_support::{sp_runtime::BuildStorage, derive_impl, construct_runtime};

use crate::{self as coins, CoinsInstance};

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Timestamp: pallet_timestamp,
    Core: serai_core_pallet,
    Coins: coins::<CoinsInstance>,
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

impl crate::Config<CoinsInstance> for Test {
  type AllowMint = crate::AlwaysAllowMint;
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
  let mut storage = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();

  crate::GenesisConfig::<Test, CoinsInstance> { accounts: vec![], _instance: Default::default() }
    .assimilate_storage(&mut storage)
    .unwrap();

  storage.into()
}
