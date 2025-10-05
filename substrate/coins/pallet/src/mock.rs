//! Test environment for Coins pallet.

use super::*;

use frame_support::{construct_runtime, derive_impl};

use sp_core::sr25519::Public;
use sp_runtime::{traits::IdentityLookup, BuildStorage};

use crate as coins;

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Coins: coins,
  }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
  type AccountId = Public;
  type Lookup = IdentityLookup<Self::AccountId>;
  type Block = Block;
}

impl Config for Test {
  type AllowMint = ();
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
  let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();

  crate::GenesisConfig::<Test> { accounts: vec![], _ignore: Default::default() }
    .assimilate_storage(&mut t)
    .unwrap();

  let mut ext = sp_io::TestExternalities::new(t);
  ext.execute_with(|| System::set_block_number(0));
  ext
}
