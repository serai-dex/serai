#![expect(clippy::as_conversions, clippy::same_name_method)]

use std::collections::HashSet;

use rand_core::{RngCore as _, OsRng};

use sp_core::{ConstU32, ConstU64};

use frame_support::{
  sp_runtime::DispatchError,
  weights::Weight,
  pallet_prelude::{OptionQuery, ValueQuery},
  traits::Hooks as _,
  derive_impl, construct_runtime,
};

use serai_abi::{
  primitives::{
    address::SeraiAddress,
    network_id::{NetworkId, ExternalNetworkId},
    balance::Amount,
    validator_sets::{Session, ValidatorSet, KeyShares as KeySharesStruct},
    signals::Signal,
  },
  signals::{Halted as _, Event},
};

use crate::{
  self as signals, registered_retirement_signal::RegisteredRetirementSignal, ValidatorSets as _,
};

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Timestamp: pallet_timestamp,
    Babe: pallet_babe,

    Core: serai_core_pallet,
    Signals: signals,
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

macro_rules! prefix {
  ($name: ident, $prefix: expr) => {
    struct $name;
    impl frame_support::traits::StorageInstance for $name {
      const STORAGE_PREFIX: &'static str = $prefix;
      fn pallet_prefix() -> &'static str {
        "ValidatorSets"
      }
    }
  };
}
prefix!(PrefixCurrentSession, "CurrentSession");
prefix!(PrefixKeyShares, "KeyShares");
prefix!(PrefixSelectedValidators, "SelectedValidators");
prefix!(PrefixStake, "Stake");

type StorageMapStruct<Prefix, Key, Value, Query> = frame_support::storage::types::StorageMap<
  Prefix,
  frame_support::Blake2_128Concat,
  Key,
  Value,
  Query,
>;
type CurrentSession = StorageMapStruct<PrefixCurrentSession, NetworkId, Session, OptionQuery>;
type KeyShares = StorageMapStruct<PrefixKeyShares, ValidatorSet, KeySharesStruct, OptionQuery>;
type SelectedValidators = StorageMapStruct<
  PrefixSelectedValidators,
  ValidatorSet,
  Vec<(SeraiAddress, KeySharesStruct)>,
  ValueQuery,
>;
type Stake = StorageMapStruct<PrefixStake, NetworkId, Amount, OptionQuery>;

#[doc(hidden)]
pub struct ValidatorSets;
impl crate::sealed::Sealed for ValidatorSets {}
impl crate::ValidatorSets for ValidatorSets {
  fn current_session(network: NetworkId) -> Option<Session> {
    CurrentSession::get(network)
  }
  fn key_shares(set: ValidatorSet) -> Option<KeySharesStruct> {
    KeyShares::get(set)
  }
  fn selected_validators(
    set: ValidatorSet,
  ) -> impl Iterator<Item = (SeraiAddress, KeySharesStruct)> {
    SelectedValidators::get(set).into_iter()
  }
  fn stake_for_current_validator_set(network: NetworkId) -> Option<Amount> {
    Stake::get(network)
  }
}

#[cfg(feature = "runtime-benchmarks")]
impl crate::benchmarking::BenchmarkValidatorSets for ValidatorSets {
  fn create_maximal_sessions() {
    for network in NetworkId::all() {
      let session = Session(0);
      CurrentSession::set(network, Some(session));
      let set = ValidatorSet { network, session };
      KeyShares::set(set, Some(KeySharesStruct::try_from(KeySharesStruct::MAX_PER_SET).unwrap()));
      let mut selected_validators = vec![];
      for i in 0 .. KeySharesStruct::MAX_PER_SET {
        selected_validators
          .push((SeraiAddress([u8::try_from(i).unwrap(); 32]), KeySharesStruct::ONE));
      }
      SelectedValidators::set(set, selected_validators);
      Stake::set(network, Some(Amount(1)));
    }
  }
}

#[doc(hidden)]
pub struct GetCurrentSessionForSubstrate;
impl pallet_session::GetCurrentSessionForSubstrate for GetCurrentSessionForSubstrate {
  fn get() -> u32 {
    <ValidatorSets as crate::ValidatorSets>::current_session(NetworkId::Serai).unwrap().0
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
  type MaxAuthorities = ConstU32<{ KeySharesStruct::MAX_PER_SET_U32 }>;
  type MaxNominators = ConstU32<{ KeySharesStruct::MAX_PER_SET_U32 }>;
  type KeyOwnerProof = sp_core::Void;
  type EquivocationReportSystem = ();
}

impl serai_core_pallet::Config for Test {
  const PROTOCOL_ID: [u8; 32] = [0; 32];
  const SIGNATURE_VERIFICATION_WEIGHT: Weight = Weight::zero();
  type PreInherents = ();
}

impl crate::Config for Test {
  type RetirementLockInDurationInSlots = ConstU64<201>;
  type ValidatorSets = ValidatorSets;
  type Weights = ();
}

pub(crate) fn new_test_ext() -> sp_io::TestExternalities {
  use core::marker::PhantomData;
  use serai_abi::TransactionContext as _;

  let mut externalities = sp_io::TestExternalities::new_empty();
  externalities.execute_with(|| {
    let system = frame_system::GenesisConfig::<Test>::default();
    let babe = pallet_babe::GenesisConfig {
      authorities: vec![],
      epoch_config: Default::default(),
      _config: PhantomData,
    };
    let signals = crate::GenesisConfig::<Test>::default();
    Core::genesis(&RuntimeGenesisConfig { system, babe, signals });

    CurrentSession::set(NetworkId::Serai, Some(Session(0)));

    System::reset_events();
    System::initialize(
      &1,
      &[0; 32].into(),
      &frame_support::sp_runtime::Digest {
        logs: vec![frame_support::sp_runtime::DigestItem::PreRuntime(
          serai_abi::SeraiPreExecutionDigest::CONSENSUS_ID,
          borsh::to_vec(&serai_abi::SeraiPreExecutionDigest {
            proposer: SeraiAddress([0; 32]),
            unix_time_in_millis: 0,
          })
          .unwrap(),
        )],
      },
    );
    Core::on_initialize(1);
    Core::start_transaction(0);
  });
  externalities
}

#[test]
fn retire() {
  let mut registrant = [0; 32];
  OsRng.fill_bytes(&mut registrant);
  let registrant = SeraiAddress(registrant);

  let mut validator = [0; 32];
  OsRng.fill_bytes(&mut validator);
  let validator = SeraiAddress(validator);

  let mut in_favor_of = [0; 32];
  OsRng.fill_bytes(&mut in_favor_of);

  let signal_0_id =
    (RegisteredRetirementSignal { registrant, in_favor_of, registered_at: Session(0) }).id();
  let signal_1_id =
    (RegisteredRetirementSignal { registrant, in_favor_of, registered_at: Session(1) }).id();
  let signal_2_id =
    (RegisteredRetirementSignal { registrant, in_favor_of, registered_at: Session(2) }).id();

  let mut ext = new_test_ext();
  let state_version = ext.state_version;

  let mut current_events = vec![];
  let mut emit_events = |events| {
    for event in events {
      current_events.push(serai_abi::Event::Signals(event));
    }
    assert_eq!(
      Core::events()
        .iter()
        .flat_map(IntoIterator::into_iter)
        .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
        .filter(|event| matches!(event, serai_abi::Event::Signals(_)))
        .collect::<Vec<_>>(),
      current_events
    );
  };

  ext.execute_with(|| {
    // Registering a retirement signal should work
    Signals::register_retirement_signal(Some(registrant).into(), in_favor_of).unwrap();
    emit_events(vec![Event::RetirementSignalRegistered {
      signal: signal_0_id,
      in_favor_of,
      registrant,
    }]);
    // if it hasn't already been registered
    assert_eq!(
      Signals::register_retirement_signal(Some(registrant).into(), in_favor_of).unwrap_err(),
      DispatchError::from(crate::Error::<Test>::RetirementSignalAlreadyRegistered)
    );
    // but a new session should cause the underlying signal to change, allowing registration
    CurrentSession::set(NetworkId::Serai, Some(Session(1)));
    Signals::register_retirement_signal(Some(registrant).into(), in_favor_of).unwrap();
    emit_events(vec![Event::RetirementSignalRegistered {
      signal: signal_1_id,
      in_favor_of,
      registrant,
    }]);

    CurrentSession::set(NetworkId::Serai, Some(Session(2)));
    let set = ValidatorSet { network: NetworkId::Serai, session: Session(2) };
    KeyShares::set(set, Some(KeySharesStruct::ONE));
    SelectedValidators::set(set, vec![(validator, KeySharesStruct::ONE)]);
    Stake::set(NetworkId::Serai, Some(Amount(1)));

    Signals::register_retirement_signal(Some(registrant).into(), in_favor_of).unwrap();
    emit_events(vec![Event::RetirementSignalRegistered {
      signal: signal_2_id,
      in_favor_of,
      registrant,
    }]);

    // Favoring a non-existant retirement signal should error
    assert_eq!(
      Signals::favor(
        Some(validator).into(),
        Signal::Retire { signal_id: [0; 32] },
        NetworkId::Serai
      )
      .unwrap_err(),
      DispatchError::from(crate::Error::<Test>::NonExistentRetirementSignal)
    );
    // Favoring a legacy retirement signal should error
    assert_eq!(
      Signals::favor(
        Some(validator).into(),
        Signal::Retire { signal_id: signal_0_id },
        NetworkId::Serai
      )
      .unwrap_err(),
      DispatchError::from(crate::Error::<Test>::ExpiredRetirementSignal)
    );
    // Favoring an active retirement signal should work
    Signals::favor(
      Some(validator).into(),
      Signal::Retire { signal_id: signal_1_id },
      NetworkId::Serai,
    )
    .unwrap();
    emit_events(vec![
      Event::SignalFavored {
        signal: Signal::Retire { signal_id: signal_1_id },
        by: validator,
        with_network: NetworkId::Serai,
      },
      Event::ValidatorSetInFavor { signal: Signal::Retire { signal_id: signal_1_id }, set },
      Event::RetirementSignalLockedIn { signal: signal_1_id },
    ]);

    // Favoring any retirement signal when one is locked in should error
    for signal_id in [signal_1_id, signal_2_id] {
      assert_eq!(
        Signals::favor(Some(validator).into(), Signal::Retire { signal_id }, NetworkId::Serai)
          .unwrap_err(),
        DispatchError::from(crate::Error::<Test>::RetirementSignalLockedIn)
      );
      // As should standing against one
      assert_eq!(
        Signals::stand_against(
          Some(validator).into(),
          Signal::Retire { signal_id },
          NetworkId::Serai
        )
        .unwrap_err(),
        DispatchError::from(crate::Error::<Test>::RetirementSignalLockedIn)
      );
    }
    // Revoking favor when a retirement signal is locked in should error
    assert_eq!(
      Signals::revoke_favor(
        Some(validator).into(),
        Signal::Retire { signal_id: signal_1_id },
        NetworkId::Serai
      )
      .unwrap_err(),
      DispatchError::from(crate::Error::<Test>::RetirementSignalLockedIn)
    );
  });

  // This is `mut` as it will commit every any pending changes
  let ext_clone = |ext: &mut sp_io::TestExternalities| {
    let backend = ext.as_backend();
    let root = *backend.root();
    sp_io::TestExternalities::from_raw_snapshot(
      backend.clone().backend_storage_mut().drain().into_iter().collect(),
      root,
      state_version,
    )
  };

  let slot = 500;

  ext_clone(&mut ext).execute_with(|| {
    // Starting a new block shouldn't be an issue
    Signals::on_initialize(2);

    // Continuing the blockchain, without updating the consensus rules, should produce an error
    pallet_babe::pallet::CurrentSlot::<Test>::set(slot.into());
    std::panic::catch_unwind(|| Signals::on_initialize(slot)).unwrap_err();
  });

  ext.execute_with(|| {
    // Arbitrary people shouldn't be able to revoke a retirement signal
    assert_eq!(
      Signals::revoke_retirement_signal(Some(validator).into(), signal_1_id).unwrap_err(),
      DispatchError::from(crate::Error::<Test>::NotRetirementSignalRegistrant)
    );
    // Whoever registered a retirement signal should be able to revoke it however
    Signals::revoke_retirement_signal(Some(registrant).into(), signal_1_id).unwrap();
    emit_events(vec![Event::RetirementSignalRevoked { signal: signal_1_id }]);

    // And the blockchain should no longer so retire
    pallet_babe::pallet::CurrentSlot::<Test>::set(slot.into());
    Signals::on_initialize(slot);
  });
}

#[test]
fn revoke_favor_and_stand_against() {
  let mut validator = [0; 32];
  OsRng.fill_bytes(&mut validator);
  let validator = SeraiAddress(validator);

  let mut other_validator = [0; 32];
  OsRng.fill_bytes(&mut other_validator);
  let other_validator = SeraiAddress(other_validator);

  let signal = Signal::Halt(ExternalNetworkId::Bitcoin);

  let mut ext = new_test_ext();
  let state_version = ext.state_version;

  let mut current_events = vec![];
  let emit_events = |current_events: &mut Vec<_>, events| {
    for event in events {
      current_events.push(serai_abi::Event::Signals(event));
    }
    assert_eq!(
      Core::events()
        .iter()
        .flat_map(IntoIterator::into_iter)
        .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
        .filter(|event| matches!(event, serai_abi::Event::Signals(_)))
        .collect::<Vec<_>>(),
      *current_events
    );
  };

  let serai_set = ValidatorSet { network: NetworkId::Serai, session: Session(2) };
  let bitcoin_set =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(2) };

  ext.execute_with(|| {
    CurrentSession::set(serai_set.network, Some(serai_set.session));
    KeyShares::set(serai_set, Some(KeySharesStruct::ONE));
    SelectedValidators::set(serai_set, vec![(validator, KeySharesStruct::ONE)]);
    Stake::set(serai_set.network, Some(Amount(1)));

    CurrentSession::set(bitcoin_set.network, Some(bitcoin_set.session));
    KeyShares::set(bitcoin_set, Some(KeySharesStruct::ONE));
    SelectedValidators::set(bitcoin_set, vec![(validator, KeySharesStruct::ONE)]);
    Stake::set(bitcoin_set.network, Some(Amount(2)));

    // Revoking favor which hasn't been granted should error
    assert_eq!(
      Signals::revoke_favor(Some(validator).into(), signal, serai_set.network).unwrap_err(),
      DispatchError::from(crate::Error::<Test>::RevokingNonExistentFavor)
    );

    Signals::favor(Some(validator).into(), signal, serai_set.network).unwrap();
    emit_events(
      &mut current_events,
      vec![
        Event::SignalFavored { signal, by: validator, with_network: serai_set.network },
        Event::ValidatorSetInFavor { signal, set: serai_set },
      ],
    );
  });

  // Test revoking via both `events_on_revoke` and `events_on_stand_against`

  let ext_clone = |ext: &mut sp_io::TestExternalities| {
    let backend = ext.as_backend();
    let root = *backend.root();
    sp_io::TestExternalities::from_raw_snapshot(
      backend.clone().backend_storage_mut().drain().into_iter().collect(),
      root,
      state_version,
    )
  };

  let events_on_revoke = vec![
    Event::FavorRevoked { signal, by: validator, with_network: serai_set.network },
    Event::ValidatorSetNoLongerInFavor { signal, set: serai_set },
  ];

  ext_clone(&mut ext).execute_with(|| {
    Signals::revoke_favor(Some(validator).into(), signal, serai_set.network).unwrap();
    let mut current_events = current_events.clone();
    emit_events(&mut current_events, events_on_revoke.clone());
  });

  ext.execute_with(|| {
    Signals::stand_against(Some(validator).into(), signal, serai_set.network).unwrap();
    let mut events_on_stand_against = events_on_revoke;
    events_on_stand_against.push(Event::AgainstSignal {
      signal,
      account: validator,
      with_network: serai_set.network,
    });
    emit_events(&mut current_events, events_on_stand_against.clone());

    // A validator who hasn't cast favor should also be able to stand against
    Signals::stand_against(
      Some(other_validator).into(),
      signal,
      NetworkId::External(ExternalNetworkId::Monero),
    )
    .unwrap();
    emit_events(
      &mut current_events,
      vec![Event::AgainstSignal {
        signal,
        account: other_validator,
        with_network: NetworkId::External(ExternalNetworkId::Monero),
      }],
    );
  });
}

#[test]
fn halt() {
  let mut validator = [0; 32];
  OsRng.fill_bytes(&mut validator);
  let validator = SeraiAddress(validator);

  let mut current_events = vec![];
  let mut emit_events = |events| {
    for event in events {
      current_events.push(serai_abi::Event::Signals(event));
    }
    assert_eq!(
      Core::events()
        .iter()
        .flat_map(IntoIterator::into_iter)
        .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
        .filter(|event| matches!(event, serai_abi::Event::Signals(_)))
        .collect::<Vec<_>>(),
      current_events
    );
  };

  new_test_ext().execute_with(|| {
    let set = ValidatorSet { network: NetworkId::Serai, session: Session(2) };
    CurrentSession::set(set.network, Some(Session(2)));
    KeyShares::set(set, Some(KeySharesStruct::ONE));
    SelectedValidators::set(set, vec![(validator, KeySharesStruct::ONE)]);
    Stake::set(set.network, Some(Amount(1)));

    let signal = Signal::Halt(ExternalNetworkId::Bitcoin);
    Signals::favor(Some(validator).into(), signal, NetworkId::Serai).unwrap();
    emit_events(vec![
      Event::SignalFavored { signal, by: validator, with_network: NetworkId::Serai },
      Event::ValidatorSetInFavor { signal, set },
      Event::NetworkHalted { network: ExternalNetworkId::Bitcoin },
    ]);

    assert!(Signals::halted(ExternalNetworkId::Bitcoin));
  });
}

#[test]
fn favor_lifetime() {
  let mut validator = [0; 32];
  OsRng.fill_bytes(&mut validator);
  let validator = SeraiAddress(validator);

  let mut current_events = vec![];
  let mut emit_events = |events| {
    for event in events {
      current_events.push(serai_abi::Event::Signals(event));
    }
    assert_eq!(
      Core::events()
        .iter()
        .flat_map(IntoIterator::into_iter)
        .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
        .filter(|event| matches!(event, serai_abi::Event::Signals(_)))
        .collect::<Vec<_>>(),
      current_events
    );
  };

  let mut serai_set = ValidatorSet { network: NetworkId::Serai, session: Session(2) };
  let bitcoin_set =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(2) };

  new_test_ext().execute_with(|| {
    CurrentSession::set(serai_set.network, Some(serai_set.session));
    KeyShares::set(serai_set, Some(KeySharesStruct::ONE));
    SelectedValidators::set(serai_set, vec![(validator, KeySharesStruct::ONE)]);
    Stake::set(serai_set.network, Some(Amount(1)));

    CurrentSession::set(bitcoin_set.network, Some(bitcoin_set.session));
    KeyShares::set(bitcoin_set, Some(KeySharesStruct::ONE));
    SelectedValidators::set(bitcoin_set, vec![(validator, KeySharesStruct::ONE)]);
    Stake::set(bitcoin_set.network, Some(Amount(2)));

    let signal = Signal::Halt(ExternalNetworkId::Bitcoin);
    Signals::favor(Some(validator).into(), signal, NetworkId::Serai).unwrap();
    emit_events(vec![
      Event::SignalFavored { signal, by: validator, with_network: NetworkId::Serai },
      Event::ValidatorSetInFavor { signal, set: serai_set },
    ]);

    let retally_with = SeraiAddress([0xaa; 32]);

    let advance_serai_session = |serai_set: &mut ValidatorSet| {
      let session = Session(CurrentSession::get(serai_set.network).unwrap().0 + 1);
      let old_serai_set = *serai_set;
      *serai_set = ValidatorSet { network: old_serai_set.network, session };
      CurrentSession::set(serai_set.network, Some(session));
      KeyShares::set(*serai_set, KeyShares::take(old_serai_set));
      SelectedValidators::set(*serai_set, SelectedValidators::take(old_serai_set));
      Stake::set(serai_set.network, Stake::get(old_serai_set.network));
    };

    // Advance Serai's session
    advance_serai_session(&mut serai_set);

    // Triggering a retally should cause the set to remain in favor due to the lifetime of the
    // favor expressed by its sole validator
    Signals::favor(Some(retally_with).into(), signal, NetworkId::Serai).unwrap();
    emit_events(vec![
      Event::SignalFavored { signal, by: retally_with, with_network: NetworkId::Serai },
      Event::ValidatorSetInFavor { signal, set: serai_set },
    ]);

    // But this validator should not be considered as favoring in the future
    advance_serai_session(&mut serai_set);
    Signals::favor(Some(retally_with).into(), signal, NetworkId::Serai).unwrap();
    emit_events(vec![Event::SignalFavored {
      signal,
      by: retally_with,
      with_network: NetworkId::Serai,
    }]);

    // And revoking the favor should be as if it didn't exist
    assert_eq!(
      Signals::revoke_favor(Some(validator).into(), signal, serai_set.network).unwrap_err(),
      DispatchError::from(crate::Error::<Test>::RevokingNonExistentFavor)
    );
  });
}

#[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
#[test]
fn fuzz() {
  // In order to test the tally functions, we create a variety of artificial layouts and perform a
  // variety of actions, ensuring things behave as expected along the way
  for _ in 0 .. 200 {
    new_test_ext().execute_with(|| {
      let mut networks = NetworkId::all().collect::<Vec<_>>();

      // Remove a random amount of networks
      for _ in 0 .. ((OsRng.next_u64() as usize) % (networks.len() - 1)) {
        networks.swap_remove((OsRng.next_u64() as usize) % networks.len());
      }
      assert!(!networks.is_empty());

      // Initialize with random states
      let mut sets = vec![];
      for network in networks.iter().copied() {
        let session = Session(OsRng.next_u64() as u32);
        let set = ValidatorSet { network, session };
        sets.push(set);

        CurrentSession::set(network, Some(session));

        let key_shares = 1 + ((OsRng.next_u64() as u16) % KeySharesStruct::MAX_PER_SET);
        KeyShares::set(set, Some(KeySharesStruct::try_from(key_shares).unwrap()));

        let mut remaining_key_shares = key_shares;
        let mut validators = vec![];
        while remaining_key_shares > 0 {
          let mut validator = [0; 32];
          OsRng.fill_bytes(&mut validator);
          let validator = SeraiAddress(validator);

          let mut key_shares = 1 + ((OsRng.next_u64() as u16) % remaining_key_shares);
          // Trend towards less key shares and more validators
          if (OsRng.next_u64() & 1) == 1 {
            key_shares = (key_shares / 2).max(1);
          }
          remaining_key_shares -= key_shares;

          validators.push((validator, KeySharesStruct::try_from(key_shares).unwrap()));
        }
        assert!(validators.len() <= usize::from(key_shares));
        SelectedValidators::set(set, validators);

        Stake::set(
          set.network,
          Some(Amount(OsRng.next_u64() / u64::try_from(networks.len()).unwrap())),
        );
      }

      let mut current_events = vec![];
      let mut emit_events = |events| {
        for event in events {
          current_events.push(serai_abi::Event::Signals(event));
        }
        assert_eq!(
          Core::events()
            .iter()
            .flat_map(IntoIterator::into_iter)
            .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
            .filter(|event| matches!(event, serai_abi::Event::Signals(_)))
            .collect::<Vec<_>>(),
          current_events
        );
      };

      // Chose either a halt or a retirement signal
      let (signal, final_event, numerator, denominator) = if OsRng.next_u64() & 1 == 1 {
        (
          Signal::Halt(ExternalNetworkId::Ethereum),
          Event::NetworkHalted { network: ExternalNetworkId::Ethereum },
          1,
          3,
        )
      } else {
        let registrant = SeraiAddress([0xaa; 32]);
        let in_favor_of = [0xbb; 32];
        Signals::register_retirement_signal(Some(registrant).into(), in_favor_of).unwrap();
        let signal_id = (RegisteredRetirementSignal {
          registrant,
          in_favor_of,
          registered_at: CurrentSession::get(NetworkId::Serai).unwrap(),
        })
        .id();

        emit_events(vec![Event::RetirementSignalRegistered {
          signal: signal_id,
          in_favor_of,
          registrant,
        }]);

        (Signal::Retire { signal_id }, Event::RetirementSignalLockedIn { signal: signal_id }, 4, 5)
      };

      // Perform 50 (un)favors and track the state is accurate
      let mut in_favor = HashSet::new();
      let mut sets_in_favor = HashSet::new();
      'actions: for _ in 0 .. 50 {
        let set = sets[(OsRng.next_u64() as usize) % sets.len()];

        let distance_to_favor = |in_favor: &HashSet<_>| {
          (((u16::from(KeyShares::get(set).unwrap()) * numerator) / denominator) + 1)
            .checked_sub(
              ValidatorSets::selected_validators(set)
                .filter_map(|(validator, key_shares)| {
                  in_favor.contains(&(set.network, validator)).then_some(u16::from(key_shares))
                })
                .sum::<u16>(),
            )
            .filter(|value| *value != 0)
        };
        let existing_distance_to_favor = distance_to_favor(&in_favor);

        let (validator, key_shares) = SelectedValidators::get(set)
          .into_iter()
          .nth((OsRng.next_u64() as usize) % SelectedValidators::get(set).len())
          .unwrap();
        let mut expected_events = vec![];
        let mut done = false;
        if in_favor.take(&(set.network, validator)).is_some() {
          Signals::revoke_favor(Some(validator).into(), signal, set.network).unwrap();
          expected_events.push(Event::FavorRevoked {
            signal,
            by: validator,
            with_network: set.network,
          });

          let new_distance_to_favor = distance_to_favor(&in_favor);
          if existing_distance_to_favor.is_none() && new_distance_to_favor.is_some() {
            expected_events.push(Event::ValidatorSetNoLongerInFavor { signal, set });
            assert!(sets_in_favor.take(&set).is_some());
          }
        } else {
          in_favor.insert((set.network, validator));
          Signals::favor(Some(validator).into(), signal, set.network).unwrap();

          expected_events.push(Event::SignalFavored {
            signal,
            by: validator,
            with_network: set.network,
          });
          if existing_distance_to_favor.is_some() &&
            (existing_distance_to_favor <= Some(u16::from(key_shares)))
          {
            expected_events.push(Event::ValidatorSetInFavor { signal, set });
            assert!(sets_in_favor.insert(set));
            if u128::from(
              sets_in_favor.iter().map(|set| Stake::get(set.network).unwrap().0).sum::<u64>(),
            ) >= (((u128::from(
              networks.iter().map(|network| Stake::get(network).unwrap().0).sum::<u64>(),
            ) * u128::from(numerator)) /
              u128::from(denominator)) +
              1)
            {
              expected_events.push(final_event.clone());
              done = true;
            }
          }
        }
        emit_events(expected_events);
        if done {
          break 'actions;
        }
      }
    });
  }
}
