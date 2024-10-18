//! Test environment for Coins pallet.

use super::*;

use frame_support::{
  construct_runtime,
  traits::{ConstU32, ConstU64},
};

use sp_core::{H256, sr25519::Public};
use sp_runtime::{
  traits::{BlakeTwo256, IdentityLookup},
  BuildStorage,
};

use crate as coins;

type Block = frame_system::mocking::MockBlock<Test>;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Coins: coins,
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

impl Config for Test {
  type RuntimeEvent = RuntimeEvent;

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
