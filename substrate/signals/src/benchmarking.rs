/// A `trait` to shim the validator sets as necessary for benchmarking.
pub trait BenchmarkValidatorSets {
  /// Enter into the database a session for every network, completely filled with validators.
  ///
  /// All validators MUST have equal weight and all validator sets MUST have equal stake.
  fn create_maximal_sessions();
}

#[expect(clippy::double_ended_iterator_last)]
#[allow(clippy::disallowed_methods, clippy::float_arithmetic)]
#[frame_benchmarking::v2::benchmarks(
  where
    <T as frame_system::Config>::RuntimeOrigin: From<Option<SeraiAddress>>,
    <T as frame_system::Config>::RuntimeEvent: Clone
      + TryInto<serai_core_pallet::Event<T>>
      + TryInto<frame_system::Event<T>>,
    <T as crate::Config>::ValidatorSets: BenchmarkValidatorSets,
)]
mod benchmarks {
  use serai_abi::{
    primitives::{address::*, network_id::*, validator_sets::*, signals::*},
    signals::*,
  };

  use frame_benchmarking::impl_test_function;

  use crate::{ValidatorSets as _, Config, Pallet, Call};

  use super::BenchmarkValidatorSets;

  #[expect(non_upper_case_globals)]
  const registrant: SeraiAddress = SeraiAddress([0xaa; 32]);
  #[expect(non_upper_case_globals)]
  const in_favor_of: [u8; 32] = [0xee; 32];

  #[benchmark]
  fn register_retirement_signal() {
    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(registrant)), in_favor_of);
  }

  #[benchmark]
  fn revoke_retirement_signal() {
    T::ValidatorSets::create_maximal_sessions();

    crate::Pallet::<T>::register_retirement_signal(
      T::RuntimeOrigin::from(Some(registrant)),
      in_favor_of,
    )
    .unwrap();

    // Lock the signal in
    let signal_id = (crate::registered_retirement_signal::RegisteredRetirementSignal {
      registrant,
      in_favor_of,
      registered_at: T::ValidatorSets::current_session(NetworkId::Serai).unwrap(),
    })
    .id();
    'outer: for network in NetworkId::all() {
      for (validator, _) in T::ValidatorSets::selected_validators(ValidatorSet {
        network,
        session: T::ValidatorSets::current_session(network).unwrap(),
      }) {
        crate::Pallet::<T>::favor(
          T::RuntimeOrigin::from(Some(validator)),
          Signal::Retire { signal_id },
          network,
        )
        .unwrap();

        if serai_core_pallet::Pallet::<T>::events()
          .iter()
          .flat_map(IntoIterator::into_iter)
          .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
          .filter(|event| matches!(event, serai_abi::Event::Signals(_)))
          .last() ==
          Some(serai_abi::Event::Signals(Event::RetirementSignalLockedIn { signal: signal_id }))
        {
          break 'outer;
        }
      }
    }

    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(registrant)), signal_id);
  }

  #[benchmark]
  fn favor() {
    T::ValidatorSets::create_maximal_sessions();

    crate::Pallet::<T>::register_retirement_signal(
      T::RuntimeOrigin::from(Some(registrant)),
      in_favor_of,
    )
    .unwrap();
    let signal_id = (crate::registered_retirement_signal::RegisteredRetirementSignal {
      registrant,
      in_favor_of,
      registered_at: T::ValidatorSets::current_session(NetworkId::Serai).unwrap(),
    })
    .id();

    // Favor with literally everyone else required, so this call is the tipping point
    let required_networks = (NetworkId::all().count() * 4 / 5) + 1;
    let mut networks = NetworkId::all();
    for network in (&mut networks).take(required_networks - 1) {
      for (validator, _) in T::ValidatorSets::selected_validators(ValidatorSet {
        network,
        session: T::ValidatorSets::current_session(network).unwrap(),
      }) {
        crate::Pallet::<T>::favor(
          T::RuntimeOrigin::from(Some(validator)),
          Signal::Retire { signal_id },
          network,
        )
        .unwrap();
      }
    }

    let network = networks.next().unwrap();
    let mut validators = T::ValidatorSets::selected_validators(ValidatorSet {
      network,
      session: T::ValidatorSets::current_session(network).unwrap(),
    });
    for (validator, _) in (&mut validators).take(usize::from(KeyShares::MAX_PER_SET) * 4 / 5) {
      crate::Pallet::<T>::favor(
        T::RuntimeOrigin::from(Some(validator)),
        Signal::Retire { signal_id },
        network,
      )
      .unwrap();
    }
    let (validator, _) = validators.next().unwrap();

    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(validator)), Signal::Retire { signal_id }, network);

    // Ensure _this_ caused the signal to lock in
    assert_eq!(
      serai_core_pallet::Pallet::<T>::events()
        .iter()
        .flat_map(IntoIterator::into_iter)
        .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
        .filter(|event| matches!(event, serai_abi::Event::Signals(_)))
        .last(),
      Some(serai_abi::Event::Signals(Event::RetirementSignalLockedIn { signal: signal_id }))
    );
  }

  #[benchmark]
  fn revoke_favor() {
    T::ValidatorSets::create_maximal_sessions();

    crate::Pallet::<T>::register_retirement_signal(
      T::RuntimeOrigin::from(Some(registrant)),
      in_favor_of,
    )
    .unwrap();
    let signal_id = (crate::registered_retirement_signal::RegisteredRetirementSignal {
      registrant,
      in_favor_of,
      registered_at: T::ValidatorSets::current_session(NetworkId::Serai).unwrap(),
    })
    .id();

    // Favor with literally everyone else required, so this call is the tipping point for this set
    let network = NetworkId::all().next().unwrap();
    let set =
      ValidatorSet { network, session: T::ValidatorSets::current_session(network).unwrap() };
    let mut validators = T::ValidatorSets::selected_validators(set);
    for (validator, _) in (&mut validators).take(usize::from(KeyShares::MAX_PER_SET) * 4 / 5) {
      crate::Pallet::<T>::favor(
        T::RuntimeOrigin::from(Some(validator)),
        Signal::Retire { signal_id },
        network,
      )
      .unwrap();
    }
    let (validator, _) = validators.next().unwrap();
    crate::Pallet::<T>::favor(
      T::RuntimeOrigin::from(Some(validator)),
      Signal::Retire { signal_id },
      network,
    )
    .unwrap();

    // Ensure _this_ caused the set to be in favor for this signal
    assert_eq!(
      serai_core_pallet::Pallet::<T>::events()
        .iter()
        .flat_map(IntoIterator::into_iter)
        .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
        .filter(|event| matches!(event, serai_abi::Event::Signals(_)))
        .last(),
      Some(serai_abi::Event::Signals(Event::ValidatorSetInFavor {
        signal: Signal::Retire { signal_id },
        set
      }))
    );

    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(validator)), Signal::Retire { signal_id }, network);
  }

  // This is equivalent to the benchmark for `revoke_favor`, solely calling `stand_against`, as
  // both have a heaviest path upon revoking the favor internally in a way causing a set update
  #[benchmark]
  fn stand_against() {
    T::ValidatorSets::create_maximal_sessions();

    crate::Pallet::<T>::register_retirement_signal(
      T::RuntimeOrigin::from(Some(registrant)),
      in_favor_of,
    )
    .unwrap();
    let signal_id = (crate::registered_retirement_signal::RegisteredRetirementSignal {
      registrant,
      in_favor_of,
      registered_at: T::ValidatorSets::current_session(NetworkId::Serai).unwrap(),
    })
    .id();

    // Favor with literally everyone else required, so this call is the tipping point for this set
    let network = NetworkId::all().next().unwrap();
    let set =
      ValidatorSet { network, session: T::ValidatorSets::current_session(network).unwrap() };
    let mut validators = T::ValidatorSets::selected_validators(set);
    for (validator, _) in (&mut validators).take(usize::from(KeyShares::MAX_PER_SET) * 4 / 5) {
      crate::Pallet::<T>::favor(
        T::RuntimeOrigin::from(Some(validator)),
        Signal::Retire { signal_id },
        network,
      )
      .unwrap();
    }
    let (validator, _) = validators.next().unwrap();
    crate::Pallet::<T>::favor(
      T::RuntimeOrigin::from(Some(validator)),
      Signal::Retire { signal_id },
      network,
    )
    .unwrap();

    // Ensure _this_ caused the set to be in favor for this signal
    assert_eq!(
      serai_core_pallet::Pallet::<T>::events()
        .iter()
        .flat_map(IntoIterator::into_iter)
        .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
        .filter(|event| matches!(event, serai_abi::Event::Signals(_)))
        .last(),
      Some(serai_abi::Event::Signals(Event::ValidatorSetInFavor {
        signal: Signal::Retire { signal_id },
        set
      }))
    );

    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(validator)), Signal::Retire { signal_id }, network);
  }

  frame_benchmarking::impl_benchmark_test_suite!(
    Pallet,
    crate::tests::new_test_ext(),
    crate::tests::Test
  );
}
