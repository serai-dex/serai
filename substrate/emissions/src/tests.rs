#![expect(clippy::as_conversions, clippy::same_name_method)]

use sp_core::{Encode as _, Decode as _};
use frame_support::{weights::Weight, derive_impl, construct_runtime};

use serai_abi::{
  primitives::{network_id::*, coin::*, balance::*, address::*, validator_sets::*, constants},
  economic_security::EconomicSecurity,
  TransactionContext as _,
};

use serai_coins_pallet::{self as coins, CoinsInstance, LiquidityTokensInstance};
use serai_validator_sets_pallet::Emissions as _;

use crate::{self as emissions, *};

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Timestamp: pallet_timestamp,
    Core: serai_core_pallet,
    Coins: coins::<CoinsInstance>,
    LiquidityTokens: coins::<LiquidityTokensInstance>,
    Dex: serai_dex_pallet,
    Emissions: emissions,
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
  type PreInherents = Emissions;
}

impl serai_coins_pallet::Config<CoinsInstance> for Test {
  type AllowMint = serai_coins_pallet::AlwaysAllowMint;
  type Weights = ();
}
impl serai_coins_pallet::Config<LiquidityTokensInstance> for Test {
  type AllowMint = serai_coins_pallet::AlwaysAllowMint;
  type Weights = ();
}

impl serai_dex_pallet::Config for Test {
  type Weights = ();
}

pub struct MockValidatorSets;
impl crate::ValidatorSets for MockValidatorSets {
  fn latest_decided_session(_network: NetworkId) -> Option<Session> {
    Some(Session(1))
  }
  fn total_allocated_stake_for_network(network: NetworkId) -> Amount {
    if network == NetworkId::Serai {
      Amount(10_000_000)
    } else {
      Amount(0)
    }
  }
  fn stake_for_latest_decided_validator_set(_network: NetworkId) -> Option<Amount> {
    Some(Amount(0))
  }
  fn rewards_distributed_for_set(_set: ExternalValidatorSet) -> bool {
    false
  }
}

fn set_achieved_economic_security(network: ExternalNetworkId, achieved: bool) {
  sp_io::storage::set(&(b"AchievedEconomicSecurity", network).encode(), &achieved.encode());
}

pub struct MockEconomicSecurity;
impl EconomicSecurity for MockEconomicSecurity {
  fn achieved_economic_security(network: ExternalNetworkId) -> bool {
    sp_io::storage::get(&(b"AchievedEconomicSecurity", network).encode())
      .map(|bytes| bool::decode(&mut &*bytes).unwrap())
      .unwrap_or(false)
  }
  fn sri_value(balance: ExternalBalance) -> Amount {
    balance.amount
  }
}

impl crate::Config for Test {
  type ValidatorSets = MockValidatorSets;
  type EconomicSecurity = MockEconomicSecurity;
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
    let dex = serai_dex_pallet::GenesisConfig::<Test> {
      fees: ExternalCoin::all().map(|coin| (coin, 0)).collect(),
      _config: Default::default(),
    };
    Core::genesis(&RuntimeGenesisConfig { system, coins, liquidity_tokens, dex });
  });
  externalities
}

#[test]
fn test_block_reward() {
  let reward_for_stake = |required_stake: u64, current_time: u128| -> u64 {
    let time_until_secure_by = DAYS_365.as_millis().saturating_sub(current_time);
    let blocks_until_secure_by = time_until_secure_by / constants::TARGET_BLOCK_TIME.as_millis();
    let serai_validators_stake_desired = required_stake / 4;
    let distance = serai_validators_stake_desired
      .saturating_sub(MockValidatorSets::total_allocated_stake_for_network(NetworkId::Serai).0);
    distance.div_ceil(u64::try_from(blocks_until_secure_by).unwrap())
  };

  new_test_ext().execute_with(|| {
    Core::start_transaction(0);

    // no rewards are emitted during the genesis period
    assert_eq!(Emissions::block_reward(), Amount(0));

    // mark genesis period complete
    crate::EndOfGenesisTimestamp::<Test>::set(Some(Core::current_time()));

    // we should get the initial period reward when we are in initial period
    assert!(INITIAL_PERIOD.as_millis() > 0);
    assert_eq!(Emissions::block_reward().0, INITIAL_PERIOD_REWARD_PER_BLOCK.0 / 5);

    // go past the initial period
    let current_time = INITIAL_PERIOD.as_millis();
    pallet_timestamp::Pallet::<Test>::set_timestamp(current_time.try_into().unwrap());

    // since required stake is 0 for external networks atm, we don't emit any reward
    assert_eq!(Emissions::block_reward(), Amount(0));

    // mint some external coin so that we need to have required stake
    let coin = ExternalCoin::Bitcoin;
    let mint_balance =
      Balance { coin: coin.into(), amount: Amount(10 * 10u64.pow(coin.decimals())) };
    Coins::mint(SeraiAddress([0u8; 32]), mint_balance).unwrap();

    let mut required_stake =
      (MockEconomicSecurity::sri_value(mint_balance.try_into().unwrap()).0 * 3) / 2;
    let reward = reward_for_stake(required_stake, current_time);
    assert_eq!(Emissions::block_reward().0, reward);

    // mint some more external coin for different network
    let coin = ExternalCoin::Ether;
    let mint_balance =
      Balance { coin: coin.into(), amount: Amount(10 * 10u64.pow(coin.decimals())) };
    Coins::mint(SeraiAddress([0u8; 32]), mint_balance).unwrap();

    required_stake += (MockEconomicSecurity::sri_value(mint_balance.try_into().unwrap()).0 * 3) / 2;
    let reward = reward_for_stake(required_stake, current_time);
    assert_eq!(Emissions::block_reward().0, reward);

    // make all networks reach economic security
    for network in ExternalNetworkId::all() {
      set_achieved_economic_security(network, true);
    }

    // now we should get fixed reward post economic security reward per block
    assert_eq!(Emissions::block_reward().0, POST_ECONOMIC_SECURITY_REWARD_PER_BLOCK.0 / 5);
  });
}
