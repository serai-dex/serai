#[allow(clippy::disallowed_methods, clippy::float_arithmetic)]
#[frame_benchmarking::v2::benchmarks(
  where <T as frame_system::Config>::RuntimeOrigin: From<Option<SeraiAddress>>
)]
mod benchmarks {
  use alloc::vec;

  use serai_abi::{
    primitives::{prelude::*, crypto::*},
    TransactionContext as _,
  };

  use frame_benchmarking::impl_test_function;

  use crate::{Config, Pallet, Call};

  const ALICE: SeraiAddress = SeraiAddress([0xaa; 32]);

  #[benchmark]
  fn set_keys() {
    use zeroize::Zeroizing;
    use rand_core::{RngCore as _, SeedableRng as _};
    use ciphersuite::{
      group::{ff::Field as _, GroupEncoding as _},
      WrappedGroup,
    };
    use dalek_ff_group::Ristretto;

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0; 32]);

    serai_core_pallet::Pallet::<T>::start_transaction(0);

    let network = NetworkId::External(ExternalNetworkId::Bitcoin);
    let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(1) };
    crate::Pallet::<T>::set_allocation_per_key_share(network, Amount(100));

    crate::pallet::CurrentSession::<T>::insert(network, Session(0));
    crate::pallet::LatestDecidedSession::<T>::insert(network, Session(1));
    for _ in crate::pallet::SelectedValidators::<T>::drain() {}

    // Create a maximal amount of validators
    let mut private_keys = vec![];
    let mut public_keys = vec![];
    let mut signature_participants = bitvec::vec::BitVec::<_, _>::new();
    for _ in 0 .. KeyShares::MAX_PER_SET {
      let mut validator = [0; 32];
      rng.fill_bytes(&mut validator);
      let validator = SeraiAddress(validator);

      let keys = SignedEmbeddedEllipticCurveKeys::serai(
        &mut rng.clone(),
        validator,
        &Zeroizing::new(<_>::random(&mut rng.clone())),
      );
      crate::Pallet::<T>::set_auxiliary_keys(T::RuntimeOrigin::from(Some(validator)), keys)
        .unwrap();

      let keys = SignedEmbeddedEllipticCurveKeys::bitcoin(
        &mut rng.clone(),
        validator,
        &Zeroizing::new(<_>::random(&mut rng.clone())),
        &Zeroizing::new(<_>::random(&mut rng.clone())),
      );
      crate::Pallet::<T>::set_auxiliary_keys(T::RuntimeOrigin::from(Some(validator)), keys)
        .unwrap();

      let key = <Ristretto as WrappedGroup>::F::random(&mut rng);
      private_keys.push((validator, Zeroizing::new(key)));
      let public_key = <Ristretto as WrappedGroup>::generator() * key;
      public_keys.push(public_key);
      signature_participants.push(true);
      crate::pallet::SelectedValidators::<T>::insert(
        set,
        validator,
        (sp_core::sr25519::Public::from(public_key.to_bytes()), KeyShares::ONE),
      );
    }

    let key_pair = KeyPair(
      Public([0; 32]),
      ExternalKey(vec![0; ExternalKey::MAX_SIZE as usize].try_into().unwrap()),
    );
    let signature_participants =
      serai_abi::primitives::BitVec::try_from(signature_participants).unwrap();
    #[rustfmt::skip]
    let signature = Signature::Ristretto(RistrettoSignature([
       22, 229,  73, 123, 219, 237, 210, 158,  37,  63, 122, 198,  74, 204, 155,  77,
      160, 109, 217,  66, 127, 239, 214, 254,  85, 186, 173,  72, 124,  39,  89, 119,
        0,   9, 133,  37,  44,  43, 103, 202, 130, 241,  99, 162, 150,  58,  72,  10,
       96,   2,  10,  95,  34, 196, 109, 131,  54,  91, 183,  77, 251,  84,  77, 138,
    ]));

    // We benchmark both the non-trivial `ValidateUnsigned::pre_dispatch` _and_ the execution
    #[block]
    {
      <Pallet<T> as frame_support::sp_runtime::traits::ValidateUnsigned>::pre_dispatch(
        &Call::set_keys {
          network: set.network,
          key_pair: key_pair.clone(),
          signature_participants: signature_participants.clone(),
          signature,
        },
      )
      .unwrap();
      Pallet::<T>::set_keys(
        T::RuntimeOrigin::from(None),
        set.network,
        key_pair,
        signature_participants,
        signature,
      )
      .unwrap();
    }
  }

  #[benchmark]
  fn slash_serai_validator() {
    serai_core_pallet::Pallet::<T>::start_transaction(0);

    let validator = crate::pallet::GenesisValidators::<T>::get().unwrap()[0];
    let network = NetworkId::Serai;
    crate::Pallet::<T>::set_allocation_per_key_share(network, Amount(100));

    // Populate allocations to drain
    serai_coins_pallet::Pallet::<T, serai_coins_pallet::CoinsInstance>::mint(
      validator,
      Balance { coin: Coin::Serai, amount: Amount(100) },
    )
    .unwrap();
    crate::Pallet::<T>::allocate(T::RuntimeOrigin::from(Some(validator)), network, Amount(100))
      .unwrap();

    serai_coins_pallet::Pallet::<T, serai_coins_pallet::CoinsInstance>::mint(
      serai_abi::validator_sets::address(),
      Balance { coin: Coin::Serai, amount: Amount(300) },
    )
    .unwrap();
    crate::pallet::DelayedDeallocations::<T>::insert(
      validator,
      ValidatorSet { network, session: Session(1) },
      Amount(100),
    );
    crate::pallet::DelayedDeallocations::<T>::insert(
      validator,
      ValidatorSet { network, session: Session(2) },
      Amount(100),
    );
    crate::pallet::DelayedDeallocations::<T>::insert(
      validator,
      ValidatorSet { network, session: Session(3) },
      Amount(100),
    );

    #[extrinsic_call]
    _(T::RuntimeOrigin::from(None), validator);
  }

  #[benchmark]
  fn report_slashes() {
    use zeroize::Zeroizing;
    use rand_core::{RngCore as _, SeedableRng as _};
    use ciphersuite::group::ff::Field as _;

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0; 32]);

    serai_core_pallet::Pallet::<T>::start_transaction(0);

    let network = NetworkId::External(ExternalNetworkId::Bitcoin);
    let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
    crate::Pallet::<T>::set_allocation_per_key_share(network, Amount(100));

    for _ in crate::pallet::SelectedValidators::<T>::drain() {}

    // Create a maximal amount of validators
    let mut validators = vec![];
    for _ in 0 .. KeyShares::MAX_PER_SET {
      let mut validator = [0; 32];
      rng.fill_bytes(&mut validator);
      let validator = SeraiAddress(validator);

      let keys = SignedEmbeddedEllipticCurveKeys::serai(
        &mut rng.clone(),
        validator,
        &Zeroizing::new(<_>::random(&mut rng.clone())),
      );
      crate::Pallet::<T>::set_auxiliary_keys(T::RuntimeOrigin::from(Some(validator)), keys)
        .unwrap();

      let keys = SignedEmbeddedEllipticCurveKeys::bitcoin(
        &mut rng.clone(),
        validator,
        &Zeroizing::new(<_>::random(&mut rng.clone())),
        &Zeroizing::new(<_>::random(&mut rng.clone())),
      );
      crate::Pallet::<T>::set_auxiliary_keys(T::RuntimeOrigin::from(Some(validator)), keys)
        .unwrap();

      // Give each validator a maximal amount of allocations to drain
      serai_coins_pallet::Pallet::<T, serai_coins_pallet::CoinsInstance>::mint(
        validator,
        Balance { coin: Coin::Serai, amount: Amount(100) },
      )
      .unwrap();
      crate::Pallet::<T>::allocate(T::RuntimeOrigin::from(Some(validator)), network, Amount(100))
        .unwrap();

      serai_coins_pallet::Pallet::<T, serai_coins_pallet::CoinsInstance>::mint(
        serai_abi::validator_sets::address(),
        Balance { coin: Coin::Serai, amount: Amount(300) },
      )
      .unwrap();
      crate::pallet::DelayedDeallocations::<T>::insert(
        validator,
        ValidatorSet { network, session: Session(1) },
        Amount(100),
      );
      crate::pallet::DelayedDeallocations::<T>::insert(
        validator,
        ValidatorSet { network, session: Session(2) },
        Amount(100),
      );
      crate::pallet::DelayedDeallocations::<T>::insert(
        validator,
        ValidatorSet { network, session: Session(3) },
        Amount(100),
      );

      validators.push((validator, Amount(1)));
      crate::pallet::SelectedValidators::<T>::insert(
        set,
        validator,
        (sp_core::sr25519::Public::from([0; 32]), KeyShares::ONE),
      );
    }

    crate::pallet::OraclizationKeys::<T>::insert(set, Public([0; 32]));

    crate::pallet::PendingSlashReport::<T>::insert(
      set,
      crate::PendingSlashReportValue::try_from(validators).unwrap(),
    );

    let slashes =
      SlashReport(vec![Slash::Fatal; usize::from(KeyShares::MAX_PER_SET)].try_into().unwrap());
    let mut signature = [0; 64];
    signature[63] = 1 << 7;
    let signature = Signature::Ristretto(RistrettoSignature(signature));

    // We benchmark both the non-trivial `ValidateUnsigned::pre_dispatch` _and_ the execution
    #[block]
    {
      <Pallet<T> as frame_support::sp_runtime::traits::ValidateUnsigned>::pre_dispatch(
        &Call::report_slashes { set, slashes: slashes.clone(), signature },
      )
      .unwrap();
      Pallet::<T>::report_slashes(T::RuntimeOrigin::from(None), set, slashes, signature).unwrap();
    }
  }

  #[benchmark]
  fn set_auxiliary_keys() {
    use zeroize::Zeroizing;
    use rand_core::SeedableRng as _;
    use ciphersuite::group::ff::Field as _;

    let rng = rand_chacha::ChaCha20Rng::from_seed([0; 32]);

    serai_core_pallet::Pallet::<T>::start_transaction(0);

    let keys = SignedEmbeddedEllipticCurveKeys::bitcoin(
      &mut rng.clone(),
      ALICE,
      &Zeroizing::new(<_>::random(&mut rng.clone())),
      &Zeroizing::new(<_>::random(&mut rng.clone())),
    );

    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(ALICE)), keys);
  }

  #[benchmark]
  fn allocate() {
    use zeroize::Zeroizing;
    use rand_core::{RngCore as _, SeedableRng as _};
    use ciphersuite::group::ff::Field as _;

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0; 32]);

    serai_core_pallet::Pallet::<T>::start_transaction(0);

    let network = NetworkId::External(ExternalNetworkId::Bitcoin);
    crate::Pallet::<T>::set_allocation_per_key_share(network, Amount(100));

    // Create a maximal amount of validators
    for _ in 0 .. KeyShares::MAX_PER_SET {
      let mut validator = [0; 32];
      rng.fill_bytes(&mut validator);
      let validator = SeraiAddress(validator);

      let keys = SignedEmbeddedEllipticCurveKeys::serai(
        &mut rng.clone(),
        validator,
        &Zeroizing::new(<_>::random(&mut rng.clone())),
      );
      crate::Pallet::<T>::set_auxiliary_keys(T::RuntimeOrigin::from(Some(validator)), keys)
        .unwrap();

      let keys = SignedEmbeddedEllipticCurveKeys::bitcoin(
        &mut rng.clone(),
        validator,
        &Zeroizing::new(<_>::random(&mut rng.clone())),
        &Zeroizing::new(<_>::random(&mut rng.clone())),
      );
      crate::Pallet::<T>::set_auxiliary_keys(T::RuntimeOrigin::from(Some(validator)), keys)
        .unwrap();

      serai_coins_pallet::Pallet::<T, serai_coins_pallet::CoinsInstance>::mint(
        validator,
        Balance { coin: Coin::Serai, amount: Amount(100) },
      )
      .unwrap();
      crate::Pallet::<T>::allocate(T::RuntimeOrigin::from(Some(validator)), network, Amount(100))
        .unwrap();
    }

    // Set this validator as present in `SelectedValidators` to trigger the worst-case within
    // the `Sessions` abstraction
    crate::pallet::CurrentSession::<T>::insert(network, Session(0));
    crate::pallet::CurrentAllocatedStake::<T>::insert(network, Amount(0));
    crate::pallet::LatestDecidedSession::<T>::insert(network, Session(1));
    crate::pallet::LatestDecidedAllocatedStake::<T>::insert(network, Amount(0));
    crate::pallet::SelectedValidators::<T>::insert(
      ValidatorSet { network, session: Session(0) },
      ALICE,
      (sp_core::sr25519::Public::from([0; 32]), KeyShares::ONE),
    );
    crate::pallet::SelectedValidators::<T>::insert(
      ValidatorSet { network, session: Session(1) },
      ALICE,
      (sp_core::sr25519::Public::from([0; 32]), KeyShares::ONE),
    );

    let keys = SignedEmbeddedEllipticCurveKeys::serai(
      &mut rng.clone(),
      ALICE,
      &Zeroizing::new(<_>::random(&mut rng.clone())),
    );
    crate::Pallet::<T>::set_auxiliary_keys(T::RuntimeOrigin::from(Some(ALICE)), keys).unwrap();

    let keys = SignedEmbeddedEllipticCurveKeys::bitcoin(
      &mut rng.clone(),
      ALICE,
      &Zeroizing::new(<_>::random(&mut rng.clone())),
      &Zeroizing::new(<_>::random(&mut rng.clone())),
    );
    crate::Pallet::<T>::set_auxiliary_keys(T::RuntimeOrigin::from(Some(ALICE)), keys).unwrap();

    serai_coins_pallet::Pallet::<T, serai_coins_pallet::CoinsInstance>::mint(
      ALICE,
      Balance { coin: Coin::Serai, amount: Amount(100) },
    )
    .unwrap();
    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(ALICE)), network, Amount(100));
  }

  #[benchmark]
  fn deallocate() {
    use zeroize::Zeroizing;
    use rand_core::{RngCore as _, SeedableRng as _};
    use ciphersuite::group::ff::Field as _;

    let mut rng = rand_chacha::ChaCha20Rng::from_seed([0; 32]);

    serai_core_pallet::Pallet::<T>::start_transaction(0);

    let network = NetworkId::External(ExternalNetworkId::Bitcoin);
    crate::Pallet::<T>::set_allocation_per_key_share(network, Amount(100));

    // Create a maximal amount of validators
    for _ in 0 .. KeyShares::MAX_PER_SET {
      let mut validator = [0; 32];
      rng.fill_bytes(&mut validator);
      let validator = SeraiAddress(validator);

      let keys = SignedEmbeddedEllipticCurveKeys::serai(
        &mut rng.clone(),
        validator,
        &Zeroizing::new(<_>::random(&mut rng.clone())),
      );
      crate::Pallet::<T>::set_auxiliary_keys(T::RuntimeOrigin::from(Some(validator)), keys)
        .unwrap();

      let keys = SignedEmbeddedEllipticCurveKeys::bitcoin(
        &mut rng.clone(),
        validator,
        &Zeroizing::new(<_>::random(&mut rng.clone())),
        &Zeroizing::new(<_>::random(&mut rng.clone())),
      );
      crate::Pallet::<T>::set_auxiliary_keys(T::RuntimeOrigin::from(Some(validator)), keys)
        .unwrap();

      serai_coins_pallet::Pallet::<T, serai_coins_pallet::CoinsInstance>::mint(
        validator,
        Balance { coin: Coin::Serai, amount: Amount(100) },
      )
      .unwrap();
      crate::Pallet::<T>::allocate(T::RuntimeOrigin::from(Some(validator)), network, Amount(100))
        .unwrap();
    }

    // Set this validator as present in the _least recent_ relevant set's `SelectedValidators` to
    // trigger the worst-case within the `DelayedDeallocationError` abstraction
    crate::pallet::CurrentSession::<T>::insert(network, Session(2));
    crate::pallet::CurrentAllocatedStake::<T>::insert(network, Amount(0));
    crate::pallet::LatestDecidedSession::<T>::insert(network, Session(3));
    crate::pallet::LatestDecidedAllocatedStake::<T>::insert(network, Amount(0));
    crate::pallet::SelectedValidators::<T>::insert(
      ValidatorSet { network, session: Session(0) },
      ALICE,
      (sp_core::sr25519::Public::from([0; 32]), KeyShares::ONE),
    );

    let keys = SignedEmbeddedEllipticCurveKeys::serai(
      &mut rng.clone(),
      ALICE,
      &Zeroizing::new(<_>::random(&mut rng.clone())),
    );
    crate::Pallet::<T>::set_auxiliary_keys(T::RuntimeOrigin::from(Some(ALICE)), keys).unwrap();

    let keys = SignedEmbeddedEllipticCurveKeys::bitcoin(
      &mut rng.clone(),
      ALICE,
      &Zeroizing::new(<_>::random(&mut rng.clone())),
      &Zeroizing::new(<_>::random(&mut rng.clone())),
    );
    crate::Pallet::<T>::set_auxiliary_keys(T::RuntimeOrigin::from(Some(ALICE)), keys).unwrap();

    serai_coins_pallet::Pallet::<T, serai_coins_pallet::CoinsInstance>::mint(
      ALICE,
      Balance { coin: Coin::Serai, amount: Amount(100) },
    )
    .unwrap();
    crate::Pallet::<T>::allocate(T::RuntimeOrigin::from(Some(ALICE)), network, Amount(100))
      .unwrap();

    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(ALICE)), network, Amount(100));
  }

  #[benchmark]
  fn claim_deallocation() {
    serai_core_pallet::Pallet::<T>::start_transaction(0);

    serai_coins_pallet::Pallet::<T, serai_coins_pallet::CoinsInstance>::mint(
      serai_abi::validator_sets::address(),
      Balance { coin: Coin::Serai, amount: Amount(100) },
    )
    .unwrap();
    crate::pallet::DelayedDeallocations::<T>::insert(
      ALICE,
      ValidatorSet { network: NetworkId::Serai, session: Session(0) },
      Amount(100),
    );

    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(ALICE)), NetworkId::Serai, Session(0));
  }

  frame_benchmarking::impl_benchmark_test_suite!(
    Pallet,
    crate::tests::new_test_ext(),
    crate::tests::Test
  );
}
