//! Test environment for the Coins pallet.
#![expect(clippy::as_conversions, clippy::same_name_method)]

use frame_support::{sp_runtime::BuildStorage as _, weights::Weight, derive_impl, construct_runtime};

use serai_abi::primitives::address::SeraiAddress;

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
