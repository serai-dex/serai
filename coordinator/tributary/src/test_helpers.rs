use zeroize::Zeroizing;
use rand::{Rng as _, RngCore, CryptoRng};

pub(crate) use serai_mock_rpc::new_test_rng;

use ciphersuite::{group::GroupEncoding as _, WrappedGroup};
use dalek_ff_group::Ristretto;
use serai_primitives::{
  validator_sets::ExternalValidatorSet,
  test_helpers::{random_bytes, random_block_hash, random_vec_u8},
};
use dkg::Participant;
use serai_tributary_types::{
  TributaryValidator, TributaryValidatorSet, test_helpers::random_tributary_validator,
};

use tendermint::{
  SignedMessage, Message, Data,
  ext::{BlockNumber, RoundNumber},
};
use tributary_sdk::{P2p, tendermint::TendermintBlock};

use messages::sign::VariantSignId;
use serai_coordinator_substrate::{
  TributaryValidatorSetInfo, test_helpers::random_tributary_validator_set_info,
};

use crate::*;

/// A P2P implementation which is a NOP and does nothing.
#[derive(Clone)]
pub struct NopP2p;
impl P2p for NopP2p {
  fn broadcast(&self, _: [u8; 32], _: Vec<u8>) -> impl Send + core::future::Future<Output = ()> {
    async {}
  }
}

/// Generate a random `Participant` (1-indexed, capped at 1).
pub fn random_participant<R: RngCore + CryptoRng>(rng: &mut R) -> Participant {
  Participant::new(rng.gen::<u16>().min(1)).unwrap()
}

/// Generate a random Ristretto scalar key (zeroized).
pub(crate) fn random_key<R: RngCore + CryptoRng>(
  rng: &mut R,
) -> Zeroizing<<Ristretto as WrappedGroup>::F> {
  Zeroizing::new(<Ristretto as WrappedGroup>::F::random(&mut *rng))
}

/// Generate a random `Signed` with the signer set to match a validator's auxiliary key.
///
/// This creates a `Signed` whose `signer` field corresponds to the `serai_networks_auxiliary_key`
/// of the validator at the given consensus index (1-based). This is needed because
/// `handle_application_tx` calls `get_consensus_index_by_serai_auxiliary(signer.to_bytes())`
/// and will ignore transactions whose signer doesn't match any validator.
pub fn random_signed_for_validator<R: RngCore + CryptoRng>(
  rng: &mut R,
  tributary_validator_set_info: &TributaryValidatorSetInfo,
  participant: Participant,
) -> Signed {
  let validator = tributary_validator_set_info
    .tributary_validator_set
    .get_tributary_validator_by_consensus_index(&participant)
    .expect("participant not in validator set");
  let signer = <Ristretto as WrappedGroup>::G::from_bytes(&validator.serai_networks_auxiliary_key)
    .expect("invalid serai_networks_auxiliary_key in validator");
  let signed = tributary_sdk::tests::random_signed(&mut *rng);
  Signed { participant, signer, signature: signed.signature }
}

/// Generate a random `Signed` with a random participant index.
pub fn random_signed<R: RngCore + CryptoRng>(rng: &mut R) -> Signed {
  let signed = tributary_sdk::tests::random_signed(&mut *rng);
  Signed {
    participant: random_participant(rng),
    signer: signed.signer,
    signature: signed.signature,
  }
}

/// Generate a random `VariantSignId` (currently always `Transaction`).
pub fn random_variant_sign_id<R: RngCore + CryptoRng>(rng: &mut R) -> VariantSignId {
  // TODO: Randomly select a variant
  VariantSignId::Transaction(random_bytes(rng))
}

/// One of each signed transaction kind, and attempts: at 0 and a random attempt.
#[expect(clippy::large_types_passed_by_value)]
pub fn all_signed_transactions_and_attempts<R: RngCore + CryptoRng>(
  rng: &mut R,
  signed: Signed,
  slash_report_len: Option<usize>,
) -> Vec<Transaction> {
  let random_attempt = rng.next_u64().saturating_add(1);
  let slash_report_len = slash_report_len.unwrap_or(3);
  vec![
    // RemoveParticipant
    Transaction::RemoveParticipant { participant: random_participant(rng), signed },
    // DkgParticipation
    Transaction::DkgParticipation { participation: random_vec_u8(rng, 0 ..= 128), signed },
    // DkgConfirmationPreprocess
    Transaction::DkgConfirmationPreprocess { attempt: 0, preprocess: random_bytes(rng), signed },
    Transaction::DkgConfirmationPreprocess {
      attempt: random_attempt,
      preprocess: random_bytes(rng),
      signed,
    },
    // DkgConfirmationShare
    Transaction::DkgConfirmationShare { attempt: 0, share: random_bytes(rng), signed },
    Transaction::DkgConfirmationShare { attempt: random_attempt, share: random_bytes(rng), signed },
    // Sign Preprocess
    Transaction::Sign {
      id: VariantSignId::Transaction(random_bytes(rng)),
      attempt: 0,
      round: SigningProtocolRound::Preprocess,
      data: HashMap::from([(random_participant(rng), random_vec_u8(rng, 0 ..= 128))]),
      signed,
    },
    Transaction::Sign {
      id: VariantSignId::Transaction(random_bytes(rng)),
      attempt: random_attempt,
      round: SigningProtocolRound::Preprocess,
      data: HashMap::from([(random_participant(rng), random_vec_u8(rng, 0 ..= 128))]),
      signed,
    },
    // Sign Share
    Transaction::Sign {
      id: VariantSignId::Batch(random_bytes(rng)),
      attempt: 0,
      round: SigningProtocolRound::Share,
      data: HashMap::from([
        (random_participant(rng), random_vec_u8(rng, 0 ..= 128)),
        (random_participant(rng), random_vec_u8(rng, 0 ..= 128)),
      ]),
      signed,
    },
    Transaction::Sign {
      id: VariantSignId::Batch(random_bytes(rng)),
      attempt: random_attempt,
      round: SigningProtocolRound::Share,
      data: HashMap::from([
        (random_participant(rng), random_vec_u8(rng, 0 ..= 128)),
        (random_participant(rng), random_vec_u8(rng, 0 ..= 128)),
      ]),
      signed,
    },
    // SlashReport
    Transaction::SlashReport {
      slash_points: (0 .. slash_report_len).map(|_| rng.next_u32()).collect(),
      signed,
    },
  ]
}

/// One of each provided transaction kind.
pub fn all_provided_transactions<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<Transaction> {
  vec![
    Transaction::Cosign { substrate_block_hash: random_block_hash(rng) },
    Transaction::Cosigned { substrate_block_hash: random_block_hash(rng) },
    Transaction::SubstrateBlock { hash: random_block_hash(rng) },
    Transaction::Batch { hash: random_bytes(rng) },
  ]
}

/// One of each of all transaction kinds.
pub fn all_transactions<R: RngCore + CryptoRng + Clone>(rng: &mut R) -> Vec<Transaction> {
  let mut txs = all_signed_transactions_and_attempts(rng, random_signed(&mut R::clone(rng)), None);
  txs.extend(all_provided_transactions(rng));
  txs
}

/// The topic for a sign protocol for a just-recognized ID.
pub fn initial_sign_topic(id: VariantSignId) -> Topic {
  Topic::Sign { id, attempt: 0, round: SigningProtocolRound::Preprocess }
}

/// Assert that no messages remain in either the processor or DKG confirmation queues.
pub fn assert_no_pending_messages(txn: &mut impl serai_db::DbTxn, set: ExternalValidatorSet) {
  assert!(
    crate::ProcessorMessages::try_recv(txn, set).is_none(),
    "unexpected remaining `ProcessorMessages`",
  );
  assert!(
    crate::DkgConfirmationMessages::try_recv(txn, set).is_none(),
    "unexpected remaining `DkgConfirmationMessages`",
  );
}

/// Assert the DB invariants established by `TributaryDb::start_cosigning`:
/// - `ActivelyCosigning` is set to the given block hash.
/// - The cosign topic is recognized (`AccumulatedWeight` initialized).
/// - The cosign topic was queued for recognition (`RecognizedTopics`).
pub fn assert_start_cosigning_invariants(
  txn: &mut impl serai_db::DbTxn,
  set: ExternalValidatorSet,
  block_hash: serai_primitives::BlockHash,
  block_number: u64,
) {
  let expected_topic = initial_sign_topic(VariantSignId::Cosign(block_number));

  assert_eq!(
    ActivelyCosigningHash::get(txn, set),
    Some(block_hash),
    "ActivelyCosigning should be set to the block hash after start_cosigning"
  );
  assert!(
    RecognizedTopics::is_topic_recognized(txn, set, expected_topic),
    "cosign topic should be recognized after start_cosigning"
  );
  assert_eq!(
    RecognizedTopics::try_recv_topic_requiring_recognition(txn, set),
    Some(expected_topic),
    "cosign topic should be queued for recognition after start_cosigning"
  );
}

/// Construct a `borsh`-encoded `SignedMessage` for our `TendermintNetwork`.
pub fn make_signed_message_bytes(sender: [u8; 32]) -> Vec<u8> {
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
pub fn assert_block_side_effects(
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
            RecognizedTopics::is_topic_recognized(txn, set, Topic::SlashReport),
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

/// Generate `n` random validators (weight 1 each) and return the
/// corresponding [`TributaryValidatorSetInfo`].
pub fn setup_n_validators<R: RngCore + CryptoRng>(
  rng: &mut R,
  n: u16,
) -> TributaryValidatorSetInfo {
  let tributary_validators: Vec<TributaryValidator> =
    (0 .. n).map(|_| random_tributary_validator(rng, 1)).collect();

  let tributary_validator_set = TributaryValidatorSet::new(tributary_validators);

  random_tributary_validator_set_info(rng, tributary_validator_set)
}
