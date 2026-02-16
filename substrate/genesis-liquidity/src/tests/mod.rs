#![expect(clippy::as_conversions, clippy::same_name_method)]

use sp_core::{Pair as _, sr25519::Pair};
use sp_keyring::sr25519::Keyring;

use frame_support::{weights::Weight, derive_impl, construct_runtime};

use serai_abi::{
  primitives::{
    network_id::*, coin::*, balance::*, crypto::EmbeddedEllipticCurveKeys, validator_sets::*,
    genesis_liquidity::GenesisValues, address::*,
  },
  economic_security::EconomicSecurity,
  genesis_liquidity::Event,
  TransactionContext as _,
};

use serai_coins_pallet::{
  self as coins, CoinsInstance, LiquidityTokensInstance, GenesisLiquidityTokensInstance,
};

use serai_dex_pallet as dex;

use crate as genesis_liquidity;

mod oraclize_values;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Timestamp: pallet_timestamp,
    Core: serai_core_pallet,
    Coins: coins::<CoinsInstance>,
    LiquidityTokens: coins::<LiquidityTokensInstance>,
    GenesisLiquidityTokens: coins::<GenesisLiquidityTokensInstance>,
    Dex: dex,
    GenesisLiquidity: genesis_liquidity,
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
impl serai_coins_pallet::Config<GenesisLiquidityTokensInstance> for Test {
  type AllowMint = serai_coins_pallet::AlwaysAllowMint;
  type Weights = ();
}

impl serai_dex_pallet::Config for Test {
  type Weights = ();
}

#[expect(unused)]
impl crate::ValidatorSets for () {
  fn set_allocation_per_key_share(network: NetworkId, allocation_per_key_share: Amount) {}

  fn current_session(network: NetworkId) -> Option<Session> {
    Some(Session(0)) // TODO
  }

  fn key_shares(set: ValidatorSet) -> Option<KeyShares> {
    Some(KeyShares::try_from(4).unwrap())
  }

  fn selected_validators(set: ValidatorSet) -> impl Iterator<Item = (SeraiAddress, KeyShares)> {
    [
      (SeraiAddress(Keyring::AliceStash.to_raw_public()), KeyShares::ONE),
      (SeraiAddress(Keyring::BobStash.to_raw_public()), KeyShares::ONE),
      (SeraiAddress(Keyring::CharlieStash.to_raw_public()), KeyShares::ONE),
      (SeraiAddress(Keyring::DaveStash.to_raw_public()), KeyShares::ONE),
    ]
    .into_iter()
  }

  fn auxiliary_keys(
    validator: SeraiAddress,
    network: NetworkId,
  ) -> Option<EmbeddedEllipticCurveKeys> {
    assert_eq!(network, NetworkId::Serai);
    Some(EmbeddedEllipticCurveKeys::Serai(
      (if validator == SeraiAddress(Keyring::AliceStash.to_raw_public()) {
        Keyring::Alice.to_raw_public()
      } else if validator == SeraiAddress(Keyring::BobStash.to_raw_public()) {
        Keyring::Bob.to_raw_public()
      } else if validator == SeraiAddress(Keyring::CharlieStash.to_raw_public()) {
        Keyring::Charlie.to_raw_public()
      } else if validator == SeraiAddress(Keyring::DaveStash.to_raw_public()) {
        Keyring::Dave.to_raw_public()
      } else {
        unreachable!()
      }),
    ))
  }

  fn network_stake_requirement(network: ExternalNetworkId) -> Amount {
    Amount(0) // TODO
  }
}

pub struct DummyEconomicSecurity;
#[expect(unused)]
impl EconomicSecurity for DummyEconomicSecurity {
  fn achieved_economic_security(network: ExternalNetworkId) -> bool {
    false // TODO
  }
  fn sri_value(balance: ExternalBalance) -> Amount {
    Amount(0) // TODO
  }
}

impl crate::Config for Test {
  type EconomicSecurity = DummyEconomicSecurity;
  type ValidatorSets = ();
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
    let genesis_liquidity_tokens =
      serai_coins_pallet::GenesisConfig::<Test, GenesisLiquidityTokensInstance> {
        accounts: vec![],
        _instance: Default::default(),
      };
    let dex = serai_dex_pallet::GenesisConfig::<Test> {
      fees: ExternalCoin::all().map(|coin| (coin, 0)).collect(),
      _config: Default::default(),
    };
    Core::genesis(&RuntimeGenesisConfig {
      system,
      coins,
      liquidity_tokens,
      genesis_liquidity_tokens,
      dex,
    });
  });
  externalities
}
