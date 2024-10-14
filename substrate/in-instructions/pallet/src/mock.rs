//! Test environment for InInstructions pallet.

use super::*;

use std::collections::HashMap;

use frame_support::{
  construct_runtime,
  traits::{ConstU16, ConstU32, ConstU64},
};

use sp_core::{H256, Pair, sr25519::Public};
use sp_runtime::{
  traits::{BlakeTwo256, IdentityLookup},
  BuildStorage,
};

use validator_sets::{primitives::MAX_KEY_SHARES_PER_SET, MembershipProof};

pub use crate as in_instructions;
pub use coins_pallet as coins;
pub use validator_sets_pallet as validator_sets;
pub use genesis_liquidity_pallet as genesis_liquidity;
pub use emissions_pallet as emissions;
pub use dex_pallet as dex;
pub use pallet_babe as babe;
pub use pallet_grandpa as grandpa;
pub use pallet_timestamp as timestamp;
pub use economic_security_pallet as economic_security;

type Block = frame_system::mocking::MockBlock<Test>;
// Maximum number of authorities per session.
pub type MaxAuthorities = ConstU32<{ MAX_KEY_SHARES_PER_SET }>;

pub const MEDIAN_PRICE_WINDOW_LENGTH: u16 = 10;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Timestamp: timestamp,
    Coins: coins,
    LiquidityTokens: coins::<Instance1>::{Pallet, Call, Storage, Event<T>},
    Emissions: emissions,
    ValidatorSets: validator_sets,
    GenesisLiquidity: genesis_liquidity,
    EconomicSecurity: economic_security,
    Dex: dex,
    Babe: babe,
    Grandpa: grandpa,
    InInstructions: in_instructions,
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

impl validator_sets::Config for Test {
  type RuntimeEvent = RuntimeEvent;
  type ShouldEndSession = Babe;
}

impl genesis_liquidity::Config for Test {
  type RuntimeEvent = RuntimeEvent;
}

impl emissions::Config for Test {
  type RuntimeEvent = RuntimeEvent;
}

impl economic_security::Config for Test {
  type RuntimeEvent = RuntimeEvent;
}

impl Config for Test {
  type RuntimeEvent = RuntimeEvent;
}

// Amounts for single key share per network
pub fn key_shares() -> HashMap<NetworkId, Amount> {
  HashMap::from([
    (NetworkId::Serai, Amount(50_000 * 10_u64.pow(8))),
    (NetworkId::External(ExternalNetworkId::Bitcoin), Amount(1_000_000 * 10_u64.pow(8))),
    (NetworkId::External(ExternalNetworkId::Ethereum), Amount(1_000_000 * 10_u64.pow(8))),
    (NetworkId::External(ExternalNetworkId::Monero), Amount(100_000 * 10_u64.pow(8))),
  ])
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
  let mut t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
  let networks: Vec<(NetworkId, Amount)> = key_shares().into_iter().collect::<Vec<_>>();

  let accounts: Vec<Public> = vec![
    insecure_pair_from_name("Alice").public(),
    insecure_pair_from_name("Bob").public(),
    insecure_pair_from_name("Charlie").public(),
    insecure_pair_from_name("Dave").public(),
    insecure_pair_from_name("Eve").public(),
    insecure_pair_from_name("Ferdie").public(),
  ];
  let validators = accounts.clone();

  coins::GenesisConfig::<Test> {
    accounts: accounts
      .into_iter()
      .map(|a| (a, Balance { coin: Coin::Serai, amount: Amount(1 << 60) }))
      .collect(),
    _ignore: Default::default(),
  }
  .assimilate_storage(&mut t)
  .unwrap();

  validator_sets::GenesisConfig::<Test> {
    networks: networks.clone(),
    participants: validators.clone(),
  }
  .assimilate_storage(&mut t)
  .unwrap();

  let mut ext = sp_io::TestExternalities::new(t);
  ext.execute_with(|| System::set_block_number(0));
  ext
}
