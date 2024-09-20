//! Test environment for ValidatorSets pallet.

use super::*;

use std::collections::HashMap;

use frame_support::{
  construct_runtime,
  traits::{ConstU16, ConstU32, ConstU64},
};

use sp_core::{
  H256, Pair as PairTrait,
  sr25519::{Public, Pair},
};
use sp_runtime::{
  traits::{BlakeTwo256, IdentityLookup},
  BuildStorage,
};

use serai_primitives::*;
use validator_sets::{primitives::MAX_KEY_SHARES_PER_SET, MembershipProof};

pub use crate as validator_sets;
pub use coins_pallet as coins;
pub use dex_pallet as dex;
pub use pallet_babe as babe;
pub use pallet_grandpa as grandpa;
pub use pallet_timestamp as timestamp;

type Block = frame_system::mocking::MockBlock<Test>;
// Maximum number of authorities per session.
pub type MaxAuthorities = ConstU32<{ MAX_KEY_SHARES_PER_SET }>;

pub const PRIMARY_PROBABILITY: (u64, u64) = (1, 4);
pub const BABE_GENESIS_EPOCH_CONFIG: sp_consensus_babe::BabeEpochConfiguration =
  sp_consensus_babe::BabeEpochConfiguration {
    c: PRIMARY_PROBABILITY,
    allowed_slots: sp_consensus_babe::AllowedSlots::PrimaryAndSecondaryPlainSlots,
  };

pub const MEDIAN_PRICE_WINDOW_LENGTH: u16 = 10;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Timestamp: timestamp,
    Coins: coins,
    LiquidityTokens: coins::<Instance1>::{Pallet, Call, Storage, Event<T>},
    ValidatorSets: validator_sets,
    Dex: dex,
    Babe: babe,
    Grandpa: grandpa,
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

impl timestamp::Config for Test {
  type Moment = u64;
  type OnTimestampSet = Babe;
  type MinimumPeriod = ConstU64<{ (TARGET_BLOCK_TIME * 1000) / 2 }>;
  type WeightInfo = ();
}

impl babe::Config for Test {
  type EpochDuration = ConstU64<{ FAST_EPOCH_DURATION }>;

  type ExpectedBlockTime = ConstU64<{ TARGET_BLOCK_TIME * 1000 }>;
  type EpochChangeTrigger = babe::ExternalTrigger;
  type DisabledValidators = ValidatorSets;

  type WeightInfo = ();
  type MaxAuthorities = MaxAuthorities;

  type KeyOwnerProof = MembershipProof<Self>;
  type EquivocationReportSystem = ();
}

impl grandpa::Config for Test {
  type RuntimeEvent = RuntimeEvent;

  type WeightInfo = ();
  type MaxAuthorities = MaxAuthorities;

  type MaxSetIdSessionEntries = ConstU64<0>;
  type KeyOwnerProof = MembershipProof<Self>;
  type EquivocationReportSystem = ();
}

impl coins::Config for Test {
  type RuntimeEvent = RuntimeEvent;
  type AllowMint = ValidatorSets;
}

impl coins::Config<coins::Instance1> for Test {
  type RuntimeEvent = RuntimeEvent;
  type AllowMint = ();
}

impl dex::Config for Test {
  type RuntimeEvent = RuntimeEvent;

  type LPFee = ConstU32<3>; // 0.3%
  type MintMinLiquidity = ConstU64<10000>;

  type MaxSwapPathLength = ConstU32<3>; // coin1 -> SRI -> coin2

  type MedianPriceWindowLength = ConstU16<{ MEDIAN_PRICE_WINDOW_LENGTH }>;

  type WeightInfo = dex::weights::SubstrateWeight<Test>;
}

impl Config for Test {
  type RuntimeEvent = RuntimeEvent;
  type ShouldEndSession = Babe;
}

// For a const we can't define
pub fn genesis_participants() -> Vec<Pair> {
  vec![
    insecure_pair_from_name("Alice"),
    insecure_pair_from_name("Bob"),
    insecure_pair_from_name("Charlie"),
    insecure_pair_from_name("Dave"),
  ]
}

// Amounts for single key share per network
pub fn key_shares() -> HashMap<NetworkId, Amount> {
  HashMap::from([
    (NetworkId::Serai, Amount(50_000 * 10_u64.pow(8))),
    (NetworkId::Bitcoin, Amount(1_000_000 * 10_u64.pow(8))),
    (NetworkId::Monero, Amount(100_000 * 10_u64.pow(8))),
    (NetworkId::Ethereum, Amount(1_000_000 * 10_u64.pow(8))),
  ])
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
  let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
  let networks: Vec<(NetworkId, Amount)> = key_shares().into_iter().collect::<Vec<_>>();

  coins::GenesisConfig::<Test> {
    accounts: genesis_participants()
      .clone()
      .into_iter()
      .map(|a| (a.public(), Balance { coin: Coin::Serai, amount: Amount(1 << 60) }))
      .collect(),
    _ignore: Default::default(),
  }
  .assimilate_storage(&mut t)
  .unwrap();

  validator_sets::GenesisConfig::<Test> {
    networks,
    participants: genesis_participants().into_iter().map(|p| p.public()).collect(),
  }
  .assimilate_storage(&mut t)
  .unwrap();

  babe::GenesisConfig::<Test> {
    authorities: genesis_participants()
      .into_iter()
      .map(|validator| (validator.public().into(), 1))
      .collect(),
    epoch_config: Some(BABE_GENESIS_EPOCH_CONFIG),
    _config: PhantomData,
  }
  .assimilate_storage(&mut t)
  .unwrap();

  grandpa::GenesisConfig::<Test> {
    authorities: genesis_participants()
      .into_iter()
      .map(|validator| (validator.public().into(), 1))
      .collect(),
    _config: PhantomData,
  }
  .assimilate_storage(&mut t)
  .unwrap();

  let mut ext = sp_io::TestExternalities::new(t);
  ext.execute_with(|| System::set_block_number(0));
  ext
}
