use core::future::Future;
use std::collections::HashMap;

use zeroize::Zeroizing;
use rand::{RngCore, CryptoRng, Rng, rngs::OsRng};

use ciphersuite::{group::GroupEncoding as _, WrappedGroup};
use dalek_ff_group::Ristretto;

use serai_primitives::{
  address::SeraiAddress,
  validator_sets::ExternalValidatorSet,
  test_helpers::{
    random_bytes, random_block_hash, random_serai_address, random_vec_u8, random_validator_set,
  },
};

use tendermint::{
  SignedMessage, Message, Data,
  ext::{BlockNumber, RoundNumber},
};
use tributary_sdk::{P2p, tendermint::TendermintBlock};

use messages::sign::VariantSignId;
use serai_coordinator_substrate::NewSetInformation;

use crate::*;

mod transaction;
mod db;
mod scan_block;
mod scan_tributary;
mod tributary;

/// A P2P implementation which is a NOP and does nothing.
#[derive(Clone)]
struct NopP2p;
impl P2p for NopP2p {
  fn broadcast(&self, _: [u8; 32], _: Vec<u8>) -> impl Send + Future<Output = ()> {
    async {}
  }
}

fn random_key<R: RngCore + CryptoRng>(rng: &mut R) -> Zeroizing<<Ristretto as WrappedGroup>::F> {
  Zeroizing::new(<Ristretto as WrappedGroup>::F::random(&mut *rng))
}

fn random_serai_address_and_key<R: RngCore + CryptoRng>(
  rng: &mut R,
) -> (<Ristretto as WrappedGroup>::G, SeraiAddress) {
  let key = Ristretto::generator() * *random_key(rng);
  (key, SeraiAddress(key.to_bytes()))
}

fn random_signed<R: RngCore + CryptoRng>(rng: &mut R) -> Signed {
  let signed = tributary_sdk::tests::random_signed(&mut *rng);
  Signed { signer: signed.signer, signature: signed.signature }
}

/// One of each signed transaction kind, and attempts: at 0 and a random attempt.
#[expect(clippy::large_types_passed_by_value)]
fn all_signed_transactions_and_attempts(signed: Signed) -> Vec<Transaction> {
  let random_attempt = OsRng.next_u64().saturating_add(1);
  vec![
    // RemoveParticipant
    Transaction::RemoveParticipant { participant: random_serai_address(&mut OsRng), signed },
    // DkgParticipation
    Transaction::DkgParticipation { participation: random_vec_u8(&mut OsRng, 0 ..= 128), signed },
    // DkgConfirmationPreprocess
    Transaction::DkgConfirmationPreprocess {
      attempt: 0,
      preprocess: random_bytes(&mut OsRng),
      signed,
    },
    Transaction::DkgConfirmationPreprocess {
      attempt: random_attempt,
      preprocess: random_bytes(&mut OsRng),
      signed,
    },
    // DkgConfirmationShare
    Transaction::DkgConfirmationShare { attempt: 0, share: random_bytes(&mut OsRng), signed },
    Transaction::DkgConfirmationShare {
      attempt: random_attempt,
      share: random_bytes(&mut OsRng),
      signed,
    },
    // Sign Preprocess
    Transaction::Sign {
      id: VariantSignId::Transaction(random_bytes(&mut OsRng)),
      attempt: 0,
      round: SigningProtocolRound::Preprocess,
      data: vec![random_vec_u8(&mut OsRng, 0 ..= 128)],
      signed,
    },
    Transaction::Sign {
      id: VariantSignId::Transaction(random_bytes(&mut OsRng)),
      attempt: random_attempt,
      round: SigningProtocolRound::Preprocess,
      data: vec![random_vec_u8(&mut OsRng, 0 ..= 128)],
      signed,
    },
    // Sign Share
    Transaction::Sign {
      id: VariantSignId::Batch(random_bytes(&mut OsRng)),
      attempt: 0,
      round: SigningProtocolRound::Share,
      data: vec![random_vec_u8(&mut OsRng, 0 ..= 128), random_vec_u8(&mut OsRng, 0 ..= 128)],
      signed,
    },
    Transaction::Sign {
      id: VariantSignId::Batch(random_bytes(&mut OsRng)),
      attempt: random_attempt,
      round: SigningProtocolRound::Share,
      data: vec![random_vec_u8(&mut OsRng, 0 ..= 128), random_vec_u8(&mut OsRng, 0 ..= 128)],
      signed,
    },
    // SlashReport
    Transaction::SlashReport { slash_points: (0 .. 3).map(|_| OsRng.next_u32()).collect(), signed },
  ]
}

/// One of each provided transaction kind.
fn all_provided_transactions() -> Vec<Transaction> {
  vec![
    Transaction::Cosign { substrate_block_hash: random_block_hash(&mut OsRng) },
    Transaction::Cosigned { substrate_block_hash: random_block_hash(&mut OsRng) },
    Transaction::SubstrateBlock { hash: random_block_hash(&mut OsRng) },
    Transaction::Batch { hash: random_bytes(&mut OsRng) },
  ]
}

/// One of each of all transaction kinds.
fn all_transactions() -> Vec<Transaction> {
  let mut txs = all_signed_transactions_and_attempts(random_signed(&mut OsRng));
  txs.extend(all_provided_transactions());
  txs
}

/// Assert that no messages remain in either the processor or DKG confirmation queues.
fn assert_no_pending_messages(txn: &mut impl serai_db::DbTxn, set: ExternalValidatorSet) {
  assert!(
    crate::ProcessorMessages::try_recv(txn, set).is_none(),
    "unexpected remaining `ProcessorMessages`",
  );
  assert!(
    crate::DkgConfirmationMessages::try_recv(txn, set).is_none(),
    "unexpected remaining `DkgConfirmationMessages`",
  );
}

fn random_variant_sign_id() -> VariantSignId {
  // TODO: Randomly select a variant
  VariantSignId::Transaction(random_bytes(&mut OsRng))
}

/// The topic for a sign protocol for a just-recognized ID.
fn initial_sign_topic(id: VariantSignId) -> Topic {
  Topic::Sign { id, attempt: 0, round: SigningProtocolRound::Preprocess }
}

/// Assert the DB invariants established by `TributaryDb::start_cosigning`:
/// - `ActivelyCosigning` is set to the given block hash.
/// - The cosign topic is recognized (`AccumulatedWeight` initialized).
/// - The cosign topic was queued for recognition (`RecognizedTopics`).
fn assert_start_cosigning_invariants(
  txn: &mut impl serai_db::DbTxn,
  set: ExternalValidatorSet,
  block_hash: serai_primitives::BlockHash,
  block_number: u64,
) {
  let expected_topic = initial_sign_topic(VariantSignId::Cosign(block_number));

  assert_eq!(
    ActivelyCosigning::get(txn, set),
    Some(block_hash),
    "ActivelyCosigning should be set to the block hash after start_cosigning"
  );
  assert!(
    RecognizedTopics::recognized(txn, set, expected_topic),
    "cosign topic should be recognized after start_cosigning"
  );
  assert_eq!(
    RecognizedTopics::try_recv_topic_requiring_recognition(txn, set),
    Some(expected_topic),
    "cosign topic should be queued for recognition after start_cosigning"
  );
}

/// Construct a `borsh`-encoded `SignedMessage` for our `TendermintNetwork`.
fn make_signed_message_bytes(sender: [u8; 32]) -> Vec<u8> {
  let msg = Message::<[u8; 32], TendermintBlock, [u8; 64]> {
    sender,
    block: BlockNumber(0),
    round: RoundNumber(0),
    data: Data::Prevote(None),
  };
  borsh::to_vec(&SignedMessage { msg, sig: [0u8; 64] }).unwrap()
}

/// Drain expected messages produced by the given transactions, then assert both queues are empty.
///
/// Some transactions produce messages on first submission (DkgParticipation, Cosign, SlashReport).
/// This function drains those expected messages before calling `assert_no_pending_messages`.
fn assert_block_side_effects(
  txn: &mut impl serai_db::DbTxn,
  set: ExternalValidatorSet,
  transactions: &[tributary_sdk::Transaction<Transaction>],
) {
  for tx in transactions {
    // TODO: Expand from checking the message is `Some(_)` to the exact expected message
    match tx {
      tributary_sdk::Transaction::Application(app_tx) => match app_tx {
        Transaction::DkgParticipation { .. } => {
          assert!(
            crate::ProcessorMessages::try_recv(txn, set).is_some(),
            "DkgParticipation should produce a processor message",
          );
        }
        Transaction::Cosign { .. } => {
          assert!(
            crate::ProcessorMessages::try_recv(txn, set).is_some(),
            "Cosign should produce a processor message",
          );
        }
        Transaction::SlashReport { .. } => {
          assert!(
            RecognizedTopics::recognized(txn, set, Topic::SlashReport),
            "SlashReport topic should be recognized",
          );
        }
        // TODO: Some of these will cause effects, but only conditionally
        Transaction::RemoveParticipant { .. } |
        Transaction::DkgConfirmationPreprocess { .. } |
        Transaction::DkgConfirmationShare { .. } |
        Transaction::Cosigned { .. } |
        Transaction::SubstrateBlock { .. } |
        Transaction::Batch { .. } |
        Transaction::Sign { .. } => {}
      },
      tributary_sdk::Transaction::Tendermint(_) => {}
    }
  }
  assert_no_pending_messages(txn, set);
}

fn new_test_set_info(validators: &[(SeraiAddress, u16)]) -> NewSetInformation {
  let set = random_validator_set(&mut OsRng);
  let serai_block_hash = random_bytes(&mut OsRng);
  let serai_block_time = OsRng.next_u64();
  let threshold = u16::try_from(
    ((usize::from(validators.iter().map(|(_validator, weight)| *weight).sum::<u16>()) * 2) / 3) + 1,
  )
  .unwrap();
  let validators = validators.to_vec();
  let evrf_public_keys = vec![];
  NewSetInformation::new(
    set,
    serai_block_hash,
    serai_block_time,
    threshold,
    validators,
    evrf_public_keys,
  )
}

type Setup = (
  Vec<(<Ristretto as WrappedGroup>::G, SeraiAddress)>,
  Vec<(SeraiAddress, u16)>,
  Vec<SeraiAddress>,
  HashMap<SeraiAddress, u16>,
  u16,
);

/// Generate `n` random validators (weight 1 each) with keys, returning all derived collections.
fn setup_n_validators_with_keys(n: u16) -> Setup {
  let keys_addrs: Vec<(<Ristretto as WrappedGroup>::G, SeraiAddress)> =
    (0 .. n).map(|_| random_serai_address_and_key(&mut OsRng)).collect();
  let validator_data: Vec<(SeraiAddress, u16)> =
    keys_addrs.iter().map(|(_, addr)| (*addr, 1u16)).collect();
  let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
  let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
  let total_weight = n;

  (keys_addrs, validator_data, validators, weights, total_weight)
}

/// Common test setup with 3 random validators each with weight 1, total_weight = 3.
fn setup_test_validators_and_weights_with_keys() -> Setup {
  setup_n_validators_with_keys(3)
}
