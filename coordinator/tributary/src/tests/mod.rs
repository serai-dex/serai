use std::collections::HashMap;

use ciphersuite::group::GroupEncoding;
use ciphersuite::WrappedGroup;
use dalek_ff_group::{Ristretto, RistrettoPoint};
use messages::sign::VariantSignId;

use rand::{CryptoRng, Rng, RngCore};
use rand_core::OsRng;

use serai_primitives::{
  address::SeraiAddress,
  test_helpers::{
    random_bytes_32, random_bytes_64, random_serai_address, random_vec_u8,
    default_test_validator_set,
  },
};

use tributary_sdk::P2p;
use zeroize::Zeroizing;
use dkg::Participant;
use serai_coordinator_substrate::NewSetInformation;

use crate::{
  db::{ActivelyCosigning, TributaryDb},
  transaction::{Signed, SigningProtocolRound, Transaction},
};

pub mod transaction;
pub mod db;
pub mod scan_block;
pub mod scan_tributary;
pub mod tributary;

#[derive(Clone)]
struct MockP2p;
impl P2p for MockP2p {
  fn broadcast(&self, _: [u8; 32], _: Vec<u8>) -> impl Send + core::future::Future<Output = ()> {
    async {}
  }
}

pub(crate) fn random_key<R: RngCore + CryptoRng>(
  rng: &mut R,
) -> Zeroizing<<Ristretto as WrappedGroup>::F> {
  Zeroizing::new(<Ristretto as WrappedGroup>::F::random(&mut *rng))
}

pub(crate) fn get_key_point(key: Zeroizing<<Ristretto as WrappedGroup>::F>) -> RistrettoPoint {
  Ristretto::generator() * *key
}

pub(crate) fn random_serai_address_and_key<R: RngCore + CryptoRng>(
  rng: &mut R,
) -> (RistrettoPoint, SeraiAddress) {
  let key = get_key_point(random_key(rng));
  (key, SeraiAddress(key.to_bytes()))
}

use crate::db::Topic;

pub(crate) fn random_signed<R: RngCore + CryptoRng>(rng: &mut R) -> Signed {
  let signed = tributary_sdk::tests::random_signed(&mut *rng);
  Signed { signer: signed.signer, signature: signed.signature }
}

/// One of each signed transaction kind, using the provided `Signed` value.
pub(crate) fn all_signed_transactions_with(signed: Signed) -> Vec<Transaction> {
  vec![
    Transaction::RemoveParticipant { participant: random_serai_address(&mut OsRng), signed },
    Transaction::DkgParticipation { participation: random_vec_u8(&mut OsRng), signed },
    Transaction::DkgConfirmationPreprocess {
      attempt: 0,
      preprocess: random_bytes_64(&mut OsRng),
      signed,
    },
    Transaction::DkgConfirmationShare { attempt: 0, share: random_bytes_32(&mut OsRng), signed },
    Transaction::Sign {
      id: VariantSignId::Transaction(random_bytes_32(&mut OsRng)),
      attempt: 0,
      round: SigningProtocolRound::Preprocess,
      data: vec![random_vec_u8(&mut OsRng)],
      signed,
    },
    Transaction::SlashReport { slash_points: (0 .. 3).map(|_| OsRng.next_u32()).collect(), signed },
  ]
}

pub(crate) fn random_transaction_id() -> VariantSignId {
  VariantSignId::Transaction(random_bytes_32(&mut OsRng))
}

/// The expected topic to be recognized after start_cosigning runs.
pub(crate) fn expected_topic_after_start_cosigning(id: VariantSignId) -> Topic {
  Topic::Sign { id, attempt: 0, round: SigningProtocolRound::Preprocess }
}

/// Assert the DB invariants established by `TributaryDb::start_cosigning`:
/// - `ActivelyCosigning` is set to the given block hash.
/// - The cosign topic is recognized (AccumulatedWeight initialized).
/// - The cosign topic was queued for recognition (RecognizedTopics).
pub(crate) fn assert_cosigning_invariants(
  txn: &mut impl serai_db::DbTxn,
  set: serai_primitives::validator_sets::ExternalValidatorSet,
  block_hash: serai_primitives::BlockHash,
  block_number: u64,
) {
  let expected_topic = expected_topic_after_start_cosigning(VariantSignId::Cosign(block_number));

  assert_eq!(
    ActivelyCosigning::get(txn, set),
    Some(block_hash),
    "ActivelyCosigning should be set to the block hash after start_cosigning"
  );
  assert!(
    TributaryDb::recognized(txn, set, expected_topic),
    "cosign topic should be recognized after start_cosigning"
  );
  assert_eq!(
    TributaryDb::try_recv_topic_requiring_recognition(txn, set),
    Some(expected_topic),
    "cosign topic should be queued for recognition after start_cosigning"
  );
}

pub(crate) fn new_test_set_info(validators: &[(SeraiAddress, u16)]) -> NewSetInformation {
  let mut participant_indexes = HashMap::new();
  let mut reverse_lookup = HashMap::new();
  let mut i = 1u16;
  for (address, weight) in validators {
    let mut indices = Vec::new();
    for _ in 0 .. *weight {
      let p = Participant::new(i).unwrap();
      indices.push(p);
      reverse_lookup.insert(p, *address);
      i += 1;
    }
    participant_indexes.insert(*address, indices);
  }

  NewSetInformation {
    set: default_test_validator_set(),
    serai_block: random_bytes_32(&mut OsRng),
    declaration_time: OsRng.next_u64(),
    threshold: OsRng.gen_range(0 ..= u16::MAX),
    validators: validators.to_vec(),
    evrf_public_keys: vec![],
    participant_indexes,
    participant_indexes_reverse_lookup: reverse_lookup,
  }
}

/// Common test setup: 3 random validators each with weight 1, total_weight = 3.
pub(crate) fn setup_test_validators_and_weights(
) -> (Vec<(SeraiAddress, u16)>, Vec<SeraiAddress>, HashMap<SeraiAddress, u16>, u16) {
  let validator_data = vec![
    (random_serai_address(&mut OsRng), 1u16),
    (random_serai_address(&mut OsRng), 1),
    (random_serai_address(&mut OsRng), 1),
  ];
  let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();

  let mut weights = HashMap::new();
  for (address, weight) in &validator_data {
    weights.insert(*address, *weight);
  }

  (validator_data, validators, weights, 3)
}

/// Like `setup_test_validators_and_weights`, but each validator also has a real key
/// so tests can produce valid `Signed` values via `new_signed`.
pub(crate) fn setup_test_validators_and_weights_with_keys() -> (
  Vec<(RistrettoPoint, SeraiAddress)>,
  Vec<(SeraiAddress, u16)>,
  Vec<SeraiAddress>,
  HashMap<SeraiAddress, u16>,
  u16,
) {
  let keys_addrs: Vec<(RistrettoPoint, SeraiAddress)> =
    (0 .. 3).map(|_| random_serai_address_and_key(&mut OsRng)).collect();
  let validator_data: Vec<(SeraiAddress, u16)> =
    keys_addrs.iter().map(|(_, addr)| (*addr, 1u16)).collect();
  let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
  let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();

  (keys_addrs, validator_data, validators, weights, 3)
}
