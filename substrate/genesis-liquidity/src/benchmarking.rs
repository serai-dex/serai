#[rustfmt::skip]
use serai_abi::primitives::{prelude::*, crypto::RistrettoSignature, genesis_liquidity::GenesisValues};

const GENESIS_VALUES: GenesisValues = GenesisValues {
  ether: Amount(10u64.pow(ExternalCoin::Bitcoin.decimals())),
  dai: Amount(10u64.pow(ExternalCoin::Bitcoin.decimals())),
  monero: Amount(10u64.pow(ExternalCoin::Bitcoin.decimals())),
};

#[rustfmt::skip]
const GENESIS_VALUES_SIGNATURE: RistrettoSignature = RistrettoSignature([
   80, 152, 170, 131, 219,  24, 217, 164, 242,  29, 185, 224, 151,  50,   5,  24,
  147, 169, 245, 252,  89, 147,  70, 250, 168,  78,  43,  41,  30, 149, 129,  68,
    2, 186,  17, 219, 217,  83,   0,  93,  21, 196, 150, 198, 128, 190,  44,   8,
  103,  25, 220, 216, 192, 180, 135, 221,  79,  19, 236,  95, 226,  72, 116, 140,
]);

/*
#[cfg(feature = "std")]
fn benchmark_signature() {
  use sp_keyring::sr25519::Keyring;
  use sp_core::Pair as _;

  use ciphersuite::{
    group::{ff::*, *},
    *,
  };
  use dalek_ff_group::Ristretto;
  use musig::Participant;

  let mut public_keys = vec![];
  for keyring in [Keyring::Alice, Keyring::Bob, Keyring::Charlie, Keyring::Dave] {
    public_keys.push(
      <Ristretto as GroupCanonicalEncoding>::from_canonical_bytes(&keyring.pair().public().0)
        .unwrap(),
    );
  }

  let context = (ValidatorSet { network: NetworkId::Serai, session: Session(0) }).musig_context();
  let mut sum_key = <Ristretto as WrappedGroup>::F::ZERO;
  for keyring in [Keyring::Alice, Keyring::Bob, Keyring::Charlie, Keyring::Dave] {
    let expanded = keyring.pair().to_raw_vec();
    assert_eq!(expanded.len(), 64);
    let private_key =
      <Ristretto as WrappedGroup>::F::from_repr((&expanded[.. 32]).try_into().unwrap()).unwrap();
    let musig_keys =
      musig::musig::<Ristretto>(context, private_key.into(), &public_keys).unwrap();
    sum_key += **musig_keys
      .view(vec![
        Participant::new(1).unwrap(),
        Participant::new(2).unwrap(),
        Participant::new(3).unwrap(),
        Participant::new(4).unwrap(),
      ])
      .unwrap()
      .secret_share();
  }
  let mut schnorrkel_key = [0; 96];
  schnorrkel_key[0 .. 32].copy_from_slice(sum_key.to_repr().as_slice());
  schnorrkel_key[64 ..]
    .copy_from_slice((<Ristretto as WrappedGroup>::generator() * sum_key).to_bytes().as_slice());
  let key_pair =
    sp_core::sr25519::Pair::from(schnorrkel::Keypair::from_bytes(&schnorrkel_key).unwrap());
  let signature = key_pair.sign(&GENESIS_VALUES.oraclize_values_message());

  // This assert doesn't work as the signature isn't deterministic
  assert_eq!(RistrettoSignature::from(signature), GENESIS_VALUES_SIGNATURE);
}
*/

#[allow(clippy::disallowed_methods, clippy::float_arithmetic)]
#[frame_benchmarking::v2::benchmarks(
  where <T as frame_system::Config>::RuntimeOrigin: From<Option<SeraiAddress>>
)]
mod benchmarks {
  use serai_abi::TransactionContext as _;

  use frame_benchmarking::impl_test_function;

  use crate::{Config, Pallet, Call};

  use super::*;

  const ALICE: SeraiAddress = SeraiAddress([0xaa; 32]);
  const BOB: SeraiAddress = SeraiAddress([0xbb; 32]);
  const TRANSFER: ExternalBalance =
    ExternalBalance { coin: ExternalCoin::Bitcoin, amount: Amount(10) };

  #[benchmark]
  fn transfer_genesis_liquidity() {
    serai_core_pallet::Pallet::<T>::start_transaction(0);
    crate::GenesisLiquidityTokens::<T>::mint(ALICE, TRANSFER.into()).unwrap();

    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(ALICE)), BOB, TRANSFER);
  }

  /*
    NOTE: This benchmarks `oraclize_values` for the static amount of validators defined in the
    tests environment. It MUST be scaled, or this methodology expanded, per the desired
    deployment.
  */
  #[benchmark]
  fn oraclize_values() {
    serai_core_pallet::Pallet::<T>::start_transaction(0);
    crate::GenesisTimestamp::<T>::set(Some(0));
    pallet_timestamp::Pallet::<T>::set_timestamp(
      u64::try_from(crate::GENESIS_LIQUIDITY_TIME.as_millis()).unwrap() + 1,
    );

    for coin in ExternalCoin::all() {
      crate::Coins::<T>::mint(
        serai_abi::genesis_liquidity::address(coin),
        (ExternalBalance { coin, amount: Amount(1_000_000) }).into(),
      )
      .unwrap();
      crate::GenesisLiquidityTokens::<T>::mint(
        ALICE,
        (ExternalBalance { coin, amount: Amount(1_000_000) }).into(),
      )
      .unwrap();
    }

    let mut bitvec = bitvec::vec::BitVec::<_, _>::new();
    for _ in 0 .. 4 {
      bitvec.push(true);
    }
    let signature_participants: serai_abi::primitives::BitVec<_> = bitvec.try_into().unwrap();

    // We benchmark both the non-trivial `ValidateUnsigned::pre_dispatch` _and_ the execution
    #[block]
    {
      <Pallet<T> as frame_support::sp_runtime::traits::ValidateUnsigned>::pre_dispatch(
        &Call::oraclize_values {
          values: GENESIS_VALUES,
          signature_participants: signature_participants.clone(),
          signature: GENESIS_VALUES_SIGNATURE,
        },
      )
      .unwrap();
      Pallet::<T>::oraclize_values(
        T::RuntimeOrigin::from(None),
        GENESIS_VALUES,
        signature_participants,
        GENESIS_VALUES_SIGNATURE,
      )
      .unwrap();
    }
  }

  #[benchmark]
  fn remove_genesis_liquidity() {
    serai_core_pallet::Pallet::<T>::start_transaction(0);
    crate::Coins::<T>::mint(
      serai_abi::dex::address(TRANSFER.coin),
      Balance { coin: Coin::Serai, amount: Amount(1_000_000) },
    )
    .unwrap();
    crate::Coins::<T>::mint(
      serai_abi::dex::address(TRANSFER.coin),
      Balance { coin: Coin::External(TRANSFER.coin), amount: Amount(1_000_000) },
    )
    .unwrap();
    crate::LiquidityTokens::<T>::mint(
      serai_abi::genesis_liquidity::address(TRANSFER.coin),
      Balance { coin: Coin::External(TRANSFER.coin), amount: Amount(1_000_000) },
    )
    .unwrap();
    crate::GenesisLiquidityTokens::<T>::mint(
      ALICE,
      (ExternalBalance { coin: TRANSFER.coin, amount: Amount(1_000_000) }).into(),
    )
    .unwrap();

    crate::Oraclized::<T>::set(Some(()));

    /*
      Despite the complexity, `remove_genesis_liquidity` is effectively without branches and
      executed as a staight line. This means so long as we perform a valid removal of genesis
      liquidity, it will be fairly benched. We don't have to contrive the heaviest possible branch.
    */
    #[extrinsic_call]
    _(T::RuntimeOrigin::from(Some(ALICE)), TRANSFER, Amount(0), Amount(0));

    // Because we didn't set `EconomicSecurityAchieved`, this should have no upside yielded
    assert_eq!(crate::Coins::<T>::balance(ALICE, Coin::Serai), Amount(0));
    assert_eq!(crate::Coins::<T>::balance(ALICE, TRANSFER.coin), TRANSFER.amount);
  }

  #[cfg(test)]
  frame_benchmarking::impl_benchmark_test_suite!(
    Pallet,
    crate::tests::new_test_ext(),
    crate::tests::Test
  );
}
