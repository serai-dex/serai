#![expect(clippy::as_conversions, clippy::same_name_method)]

use sp_core::{ConstU32, ConstU64};

use frame_support::{weights::Weight, derive_impl, construct_runtime};

use serai_abi::primitives::{
  address::SeraiAddress,
  network_id::{ExternalNetworkId, NetworkId},
  balance::{Amount, ExternalBalance},
  validator_sets::{Session, ExternalValidatorSet, KeyShares},
};

use serai_coins_pallet::CoinsInstance;

use crate::{self as validator_sets, auxiliary_keys::AuxiliaryKeys as _};

mod slash_reports;
// TODO: We _need_ a `mod sessions` to exhaustively test `attempt_new_session` and other methods

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Timestamp: pallet_timestamp,
    Babe: pallet_babe,
    Grandpa: pallet_grandpa,

    Core: serai_core_pallet,
    Coins: serai_coins_pallet::<CoinsInstance>,
    ValidatorSets: validator_sets,
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
    crate::Pallet::<Test>::current_session(NetworkId::Serai).map(|session| session.0).unwrap_or(0)
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

pub struct NeverHalted;
impl serai_abi::signals::Halted for NeverHalted {
  fn halted(_network: ExternalNetworkId) -> bool {
    false
  }
}

impl serai_coins_pallet::Config<CoinsInstance> for Test {
  type AllowMint = serai_coins_pallet::AlwaysAllowMint;
  type AllowBurnWithInstruction = NeverHalted;
  type Weights = ();
}

pub struct DummyEconomicSecurity;
#[expect(unused)]
impl serai_abi::economic_security::EconomicSecurity for DummyEconomicSecurity {
  fn achieved_economic_security(network: ExternalNetworkId) -> bool {
    true
  }
  fn sri_value(balance: ExternalBalance) -> Amount {
    Amount(0)
  }
}

#[doc(hidden)]
pub struct DummyEmissions;
impl crate::Emissions for DummyEmissions {
  fn block_reward() -> Amount {
    Amount(0)
  }
  fn take_set_reward(_set: ExternalValidatorSet) -> Amount {
    Amount(0)
  }
}

impl crate::Config for Test {
  type ShouldEndSession = Babe;
  type EconomicSecurity = DummyEconomicSecurity;
  type Emissions = DummyEmissions;
  type Weights = ();
}

#[cfg(test)]
pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
  use core::marker::PhantomData;
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
    let coins = serai_coins_pallet::GenesisConfig::<Test, CoinsInstance> {
      accounts: vec![],
      _instance: PhantomData,
    };
    let babe = pallet_babe::GenesisConfig {
      authorities: vec![],
      epoch_config: Default::default(),
      _config: PhantomData,
    };
    let grandpa = pallet_grandpa::GenesisConfig { authorities: vec![], _config: PhantomData };
    let validator_sets = crate::GenesisConfig { participants: validators.clone() };
    Core::genesis(&RuntimeGenesisConfig { system, coins, babe, grandpa, validator_sets });

    assert_eq!(
      crate::pallet::GenesisValidators::<Test>::get(),
      Some(
        validators
          .iter()
          .map(|(validator, _keys)| *validator)
          .collect::<Vec<_>>()
          .try_into()
          .unwrap()
      )
    );
    for (validator, keys) in validators {
      for keys in keys {
        let keys = keys.verify(validator).unwrap();
        assert_eq!(crate::AuxiliaryKeys::<Test>::get(keys.network(), validator), Some(keys));
        assert!(crate::Abstractions::<Test>::has_necessary_auxiliary_keys(
          validator,
          keys.network()
        ));
      }
    }
    assert_eq!(crate::CurrentSession::<Test>::get(NetworkId::Serai), Some(Session(0)));
    assert_eq!(crate::LatestDecidedSession::<Test>::get(NetworkId::Serai), Some(Session(1)));
    for network in ExternalNetworkId::all() {
      assert_eq!(crate::CurrentSession::<Test>::get(network), None);
      assert_eq!(crate::LatestDecidedSession::<Test>::get(network), Some(Session(0)));
    }
  });
  externalities
}
