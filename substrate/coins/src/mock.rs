//! Test environment for Coins pallet.

use borsh::BorshDeserialize;

use frame_support::{sp_runtime::BuildStorage, derive_impl, construct_runtime};

use crate::{self as coins, CoinsInstance};

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
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

impl serai_core_pallet::Config for Test {}

impl crate::Config<CoinsInstance> for Test {
  type AllowMint = crate::AlwaysAllowMint;
}

impl TryFrom<RuntimeEvent> for serai_abi::Event {
  type Error = ();
  fn try_from(event: RuntimeEvent) -> Result<serai_abi::Event, ()> {
    match event {
      RuntimeEvent::Core(serai_core_pallet::Event::Event(event)) => {
        Ok(serai_abi::Event::deserialize_reader(&mut event.as_slice()).unwrap())
      }
      _ => Err(()),
    }
  }
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
  let mut storage = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();

  crate::GenesisConfig::<Test, CoinsInstance> { accounts: vec![], _instance: Default::default() }
    .assimilate_storage(&mut storage)
    .unwrap();

  storage.into()
}
