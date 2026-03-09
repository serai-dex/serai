#![expect(clippy::as_conversions, clippy::same_name_method)]

use core::marker::PhantomData;

use sp_core::{ConstU32, ConstU64};

use frame_support::{weights::Weight, derive_impl, construct_runtime};

use serai_abi::primitives::{
  address::SeraiAddress,
  network_id::{ExternalNetworkId, NetworkId},
  coin::ExternalCoin,
  balance::{Amount, Balance},
  validator_sets::{ExternalValidatorSet, KeyShares},
};

use serai_coins_pallet::{CoinsInstance, LiquidityTokensInstance, GenesisLiquidityTokensInstance};

use crate as in_instructions;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Timestamp: pallet_timestamp,
    Babe: pallet_babe,
    Grandpa: pallet_grandpa,

    Core: serai_core_pallet,
    Coins: serai_coins_pallet::<CoinsInstance>,
    ValidatorSets: serai_validator_sets_pallet,
    Signals: serai_signals_pallet,
    LiquidityTokens: serai_coins_pallet::<LiquidityTokensInstance>,
    Dex: serai_dex_pallet,
    EconomicSecurity: serai_economic_security_pallet,
    GenesisLiquidityTokens: serai_coins_pallet::<GenesisLiquidityTokensInstance>,
    GenesisLiquidity: serai_genesis_liquidity_pallet,
    InInstructions: in_instructions,
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

#[doc(hidden)]
pub struct GetCurrentSessionForSubstrate;
impl pallet_session::GetCurrentSessionForSubstrate for GetCurrentSessionForSubstrate {
  fn get() -> u32 {
    ValidatorSets::current_session(NetworkId::Serai).map(|session| session.0).unwrap_or(0)
  }
}
impl pallet_session::Config for Test {
  type Session = GetCurrentSessionForSubstrate;
}

impl pallet_babe::Config for Test {
  type EpochDuration = ConstU64<100>;
  type ExpectedBlockTime = ConstU64<6000>;
  type EpochChangeTrigger = pallet_babe::ExternalTrigger;
  type DisabledValidators = ();
  type WeightInfo = ();
  type MaxAuthorities = ConstU32<{ KeyShares::MAX_PER_SET_U32 }>;
  type MaxNominators = ConstU32<{ KeyShares::MAX_PER_SET_U32 }>;
  type KeyOwnerProof = sp_core::Void;
  type EquivocationReportSystem = ();
}

impl pallet_grandpa::Config for Test {
  type RuntimeEvent = RuntimeEvent;
  type WeightInfo = ();
  type MaxAuthorities = ConstU32<{ KeyShares::MAX_PER_SET_U32 }>;
  type MaxNominators = ConstU32<{ KeyShares::MAX_PER_SET_U32 }>;
  type MaxSetIdSessionEntries = ConstU64<0>;
  type KeyOwnerProof = sp_core::Void;
  type EquivocationReportSystem = ();
}

impl serai_core_pallet::Config for Test {
  const PROTOCOL_ID: [u8; 32] = [0; 32];
  const SIGNATURE_VERIFICATION_WEIGHT: Weight = Weight::zero();
  type PreInherents = ();
}

impl serai_coins_pallet::Config<CoinsInstance> for Test {
  type AllowMint = serai_economic_security_pallet::CoinsInstanceAllowMint<Test>;
  type Weights = ();
}

#[doc(hidden)]
pub struct DummyEmissions;
impl serai_validator_sets_pallet::Emissions for DummyEmissions {
  fn block_reward() -> Amount {
    Amount(0)
  }
  fn take_set_reward(_set: ExternalValidatorSet) -> Amount {
    Amount(0)
  }
}

impl serai_validator_sets_pallet::Config for Test {
  type ShouldEndSession = Babe;
  type EconomicSecurity = EconomicSecurity;
  type Emissions = DummyEmissions;
  type Weights = ();
}

impl serai_signals_pallet::Config for Test {
  type RetirementLockInDurationInSlots = ConstU64<201>;
  type ValidatorSets = ValidatorSets;
  type Weights = ();
}

impl serai_coins_pallet::Config<LiquidityTokensInstance> for Test {
  type AllowMint = serai_economic_security_pallet::LiquidityTokensInstanceAllowMint<Test>;
  type Weights = ();
}

impl serai_dex_pallet::Config for Test {
  type Weights = ();
}

pub struct MockValidatorSets;
#[expect(unused_variables)]
impl serai_economic_security_pallet::ValidatorSets for MockValidatorSets {
  fn stake_for_current_validator_set(network: NetworkId) -> Option<Amount> {
    Some(Amount(1))
  }
  fn stake_for_latest_decided_validator_set(network: NetworkId) -> Option<Amount> {
    Some(Amount(1))
  }
  fn coins_stake_requirement(
    network: ExternalNetworkId,
    proposed_additional_balance: Option<Balance>,
  ) -> Amount {
    Amount(0)
  }
  fn liquidity_stake_requirement(network: ExternalNetworkId) -> Amount {
    Amount(0)
  }
  fn network_stake_requirement(network: ExternalNetworkId) -> Amount {
    Amount(0)
  }
}

impl serai_economic_security_pallet::Config for Test {
  // TODO: Defer to the actual `ValidatorSets` present in-runtime
  type ValidatorSets = MockValidatorSets;
}

impl serai_coins_pallet::Config<GenesisLiquidityTokensInstance> for Test {
  type AllowMint = serai_coins_pallet::AlwaysAllowMint;
  type Weights = ();
}

impl serai_genesis_liquidity_pallet::Config for Test {
  type EconomicSecurity = EconomicSecurity;
  type ValidatorSets = ValidatorSets;
  type Weights = ();
}

impl crate::Config for Test {
  type Weights = ();
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
  use zeroize::Zeroizing;
  use rand_core::{RngCore as _, OsRng};
  use ciphersuite::group::ff::Field as _;
  use serai_abi::primitives::crypto::SignedEmbeddedEllipticCurveKeys;

  let mut externalities = sp_io::TestExternalities::new_empty();
  externalities.execute_with(|| {
    let mut validator = [0; 32];
    OsRng.fill_bytes(&mut validator);
    let validator = SeraiAddress(validator);
    let validators = vec![(
      validator,
      vec![
        SignedEmbeddedEllipticCurveKeys::serai(
          &mut OsRng,
          validator,
          &Zeroizing::new(<_>::random(&mut OsRng)),
        ),
        SignedEmbeddedEllipticCurveKeys::bitcoin(
          &mut OsRng,
          validator,
          &Zeroizing::new(<_>::random(&mut OsRng)),
          &Zeroizing::new(<_>::random(&mut OsRng)),
        ),
        SignedEmbeddedEllipticCurveKeys::ethereum(
          &mut OsRng,
          validator,
          &Zeroizing::new(<_>::random(&mut OsRng)),
          &Zeroizing::new(<_>::random(&mut OsRng)),
        ),
        SignedEmbeddedEllipticCurveKeys::monero(
          &mut OsRng,
          validator,
          &Zeroizing::new(<_>::random(&mut OsRng)),
        ),
      ],
    )];

    let system = frame_system::GenesisConfig::<Test>::default();
    let babe = pallet_babe::GenesisConfig {
      authorities: vec![],
      epoch_config: Default::default(),
      _config: PhantomData,
    };
    let grandpa = pallet_grandpa::GenesisConfig { authorities: vec![], _config: PhantomData };
    let coins = serai_coins_pallet::GenesisConfig::<Test, CoinsInstance> {
      accounts: vec![],
      _instance: Default::default(),
    };
    let validator_sets =
      serai_validator_sets_pallet::GenesisConfig { participants: validators.clone() };
    let signals = serai_signals_pallet::GenesisConfig::default();
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
      babe,
      grandpa,
      coins,
      validator_sets,
      signals,
      liquidity_tokens,
      genesis_liquidity_tokens,
      dex,
    });
  });
  externalities
}
