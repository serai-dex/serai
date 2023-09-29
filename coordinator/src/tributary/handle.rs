use core::{ops::Deref, future::Future};
use std::collections::HashMap;

use zeroize::Zeroizing;

use rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;

use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::{Ciphersuite, Ristretto};
use frost::{
  FrostError,
  dkg::{Participant, musig::musig},
  sign::*,
};
use frost_schnorrkel::Schnorrkel;

use serai_client::{
  Signature,
  validator_sets::primitives::{ValidatorSet, KeyPair, musig_context, set_keys_message},
  subxt::utils::Encoded,
  Serai,
};

use tributary::Signed;

use processor_messages::{
  key_gen::{self, KeyGenId},
  coordinator,
  sign::{self, SignId},
};

use serai_db::{Get, Db};

use crate::{
  processors::Processors,
  tributary::{
    Transaction, TributarySpec, Topic, DataSpecification, TributaryDb, nonce_decider::NonceDecider,
    scanner::RecognizedIdType,
  },
};

const DKG_COMMITMENTS: &str = "commitments";
const DKG_SHARES: &str = "shares";
const DKG_CONFIRMATION_NONCES: &str = "confirmation_nonces";
const DKG_CONFIRMATION_SHARES: &str = "confirmation_shares";

// These s/b prefixes between Batch and Sign should be unnecessary, as Batch/Share entries
// themselves should already be domain separated
const BATCH_PREPROCESS: &str = "b_preprocess";
const BATCH_SHARE: &str = "b_share";

const SIGN_PREPROCESS: &str = "s_preprocess";
const SIGN_SHARE: &str = "s_share";

// Instead of maintaing state, this simply re-creates the machine(s) in-full on every call (which
// should only be once per tributary).
// This simplifies data flow and prevents requiring multiple paths.
// While more expensive, this only runs an O(n) algorithm, which is tolerable to run multiple
// times.
struct DkgConfirmer;
impl DkgConfirmer {
  fn preprocess_internal(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    attempt: u32,
  ) -> (AlgorithmSignMachine<Ristretto, Schnorrkel>, [u8; 64]) {
    // TODO: Does Substrate already have a validator-uniqueness check?
    let validators = spec.validators().iter().map(|val| val.0).collect::<Vec<_>>();

    let context = musig_context(spec.set());
    let mut chacha = ChaCha20Rng::from_seed({
      let mut entropy_transcript = RecommendedTranscript::new(b"DkgConfirmer Entropy");
      entropy_transcript.append_message(b"spec", spec.serialize());
      entropy_transcript.append_message(b"key", Zeroizing::new(key.to_bytes()));
      entropy_transcript.append_message(b"attempt", attempt.to_le_bytes());
      Zeroizing::new(entropy_transcript).rng_seed(b"preprocess")
    });
    let (machine, preprocess) = AlgorithmMachine::new(
      Schnorrkel::new(b"substrate"),
      musig(&context, key, &validators)
        .expect("confirming the DKG for a set we aren't in/validator present multiple times")
        .into(),
    )
    .preprocess(&mut chacha);

    (machine, preprocess.serialize().try_into().unwrap())
  }
  // Get the preprocess for this confirmation.
  fn preprocess(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    attempt: u32,
  ) -> [u8; 64] {
    Self::preprocess_internal(spec, key, attempt).1
  }

  fn share_internal(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    attempt: u32,
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
  ) -> Result<(AlgorithmSignatureMachine<Ristretto, Schnorrkel>, [u8; 32]), Participant> {
    let machine = Self::preprocess_internal(spec, key, attempt).0;
    let preprocesses = preprocesses
      .into_iter()
      .map(|(p, preprocess)| {
        machine
          .read_preprocess(&mut preprocess.as_slice())
          .map(|preprocess| (p, preprocess))
          .map_err(|_| p)
      })
      .collect::<Result<HashMap<_, _>, _>>()?;
    let (machine, share) = machine
      .sign(preprocesses, &set_keys_message(&spec.set(), key_pair))
      .map_err(|e| match e {
        FrostError::InternalError(e) => unreachable!("FrostError::InternalError {e}"),
        FrostError::InvalidParticipant(_, _) |
        FrostError::InvalidSigningSet(_) |
        FrostError::InvalidParticipantQuantity(_, _) |
        FrostError::DuplicatedParticipant(_) |
        FrostError::MissingParticipant(_) => unreachable!("{e:?}"),
        FrostError::InvalidPreprocess(p) | FrostError::InvalidShare(p) => p,
      })?;

    Ok((machine, share.serialize().try_into().unwrap()))
  }
  // Get the share for this confirmation, if the preprocesses are valid.
  fn share(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    attempt: u32,
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
  ) -> Result<[u8; 32], Participant> {
    Self::share_internal(spec, key, attempt, preprocesses, key_pair).map(|(_, share)| share)
  }

  fn complete(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    attempt: u32,
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
    shares: HashMap<Participant, Vec<u8>>,
  ) -> Result<[u8; 64], Participant> {
    let machine = Self::share_internal(spec, key, attempt, preprocesses, key_pair)
      .expect("trying to complete a machine which failed to preprocess")
      .0;

    let shares = shares
      .into_iter()
      .map(|(p, share)| {
        machine.read_share(&mut share.as_slice()).map(|share| (p, share)).map_err(|_| p)
      })
      .collect::<Result<HashMap<_, _>, _>>()?;
    let signature = machine.complete(shares).map_err(|e| match e {
      FrostError::InternalError(e) => unreachable!("FrostError::InternalError {e}"),
      FrostError::InvalidParticipant(_, _) |
      FrostError::InvalidSigningSet(_) |
      FrostError::InvalidParticipantQuantity(_, _) |
      FrostError::DuplicatedParticipant(_) |
      FrostError::MissingParticipant(_) => unreachable!("{e:?}"),
      FrostError::InvalidPreprocess(p) | FrostError::InvalidShare(p) => p,
    })?;

    Ok(signature.to_bytes())
  }
}

fn read_known_to_exist_data<D: Db, G: Get>(
  getter: &G,
  spec: &TributarySpec,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  data_spec: &DataSpecification,
  needed: u16,
) -> Option<HashMap<Participant, Vec<u8>>> {
  let mut data = HashMap::new();
  for validator in spec.validators().iter().map(|validator| validator.0) {
    data.insert(
      spec.i(validator).unwrap(),
      if let Some(data) = TributaryDb::<D>::data(getter, spec.genesis(), data_spec, validator) {
        data
      } else {
        continue;
      },
    );
  }
  assert_eq!(data.len(), usize::from(needed));

  // Remove our own piece of data, if we were involved
  if data
    .remove(
      &spec
        .i(Ristretto::generator() * key.deref())
        .expect("handling a message for a Tributary we aren't part of"),
    )
    .is_some()
  {
    Some(data)
  } else {
    None
  }
}

pub fn dkg_confirmation_nonces(
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  spec: &TributarySpec,
  attempt: u32,
) -> [u8; 64] {
  DkgConfirmer::preprocess(spec, key, attempt)
}

#[allow(clippy::needless_pass_by_ref_mut)]
pub fn generated_key_pair<D: Db>(
  txn: &mut D::Transaction<'_>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  spec: &TributarySpec,
  key_pair: &KeyPair,
  attempt: u32,
) -> Result<[u8; 32], Participant> {
  TributaryDb::<D>::save_currently_completing_key_pair(txn, spec.genesis(), key_pair);

  let Some(preprocesses) = read_known_to_exist_data::<D, _>(
    txn,
    spec,
    key,
    &DataSpecification { topic: Topic::Dkg, label: DKG_CONFIRMATION_NONCES, attempt },
    spec.n(),
  ) else {
    panic!("wasn't a participant in confirming a key pair");
  };
  DkgConfirmer::share(spec, key, attempt, preprocesses, key_pair)
}

pub(crate) async fn handle_application_tx<
  D: Db,
  Pro: Processors,
  FPst: Future<Output = ()>,
  PST: Clone + Fn(ValidatorSet, Encoded) -> FPst,
  FRid: Future<Output = ()>,
  RID: crate::RIDTrait<FRid>,
>(
  tx: Transaction,
  spec: &TributarySpec,
  processors: &Pro,
  publish_serai_tx: PST,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: RID,
  txn: &mut <D as Db>::Transaction<'_>,
) {
  let genesis = spec.genesis();

  let handle = |txn: &mut _, data_spec: &DataSpecification, bytes: Vec<u8>, signed: &Signed| {
    let Some(curr_attempt) = TributaryDb::<D>::attempt(txn, genesis, data_spec.topic) else {
      // TODO: Full slash
      todo!();
    };

    // If they've already published a TX for this attempt, slash
    if let Some(data) = TributaryDb::<D>::data(txn, genesis, data_spec, signed.signer) {
      if data != bytes {
        // TODO: Full slash
        todo!();
      }

      // TODO: Slash
      return None;
    }

    // If the attempt is lesser than the blockchain's, slash
    if data_spec.attempt < curr_attempt {
      // TODO: Slash for being late
      return None;
    }
    if data_spec.attempt > curr_attempt {
      // TODO: Full slash
      todo!();
    }

    // TODO: We can also full slash if shares before all commitments, or share before the
    // necessary preprocesses

    // TODO: If this is shares, we need to check they are part of the selected signing set

    // Store this data
    let received = TributaryDb::<D>::set_data(txn, genesis, data_spec, signed.signer, &bytes);

    // If we have all the needed commitments/preprocesses/shares, tell the processor
    // TODO: This needs to be coded by weight, not by validator count
    let needed = if data_spec.topic == Topic::Dkg { spec.n() } else { spec.t() };
    if received == needed {
      return Some(read_known_to_exist_data::<D, _>(txn, spec, key, data_spec, needed));
    }
    None
  };

  match tx {
    Transaction::DkgCommitments(attempt, bytes, signed) => {
      match handle(
        txn,
        &DataSpecification { topic: Topic::Dkg, label: DKG_COMMITMENTS, attempt },
        bytes,
        &signed,
      ) {
        Some(Some(commitments)) => {
          log::info!("got all DkgCommitments for {}", hex::encode(genesis));
          processors
            .send(
              spec.set().network,
              key_gen::CoordinatorMessage::Commitments {
                id: KeyGenId { set: spec.set(), attempt },
                commitments,
              },
            )
            .await;
        }
        Some(None) => panic!("wasn't a participant in DKG commitments"),
        None => {}
      }
    }

    Transaction::DkgShares { attempt, mut shares, confirmation_nonces, signed } => {
      if shares.len() != (usize::from(spec.n()) - 1) {
        // TODO: Full slash
        todo!();
      }

      let sender_i = spec
        .i(signed.signer)
        .expect("transaction added to tributary by signer who isn't a participant");

      // Only save our share's bytes
      let our_i = spec
        .i(Ristretto::generator() * key.deref())
        .expect("in a tributary we're not a validator for");

      let bytes = if sender_i == our_i {
        vec![]
      } else {
        // 1-indexed to 0-indexed, handling the omission of the sender's own data
        let relative_i = usize::from(u16::from(our_i) - 1) -
          (if u16::from(our_i) > u16::from(sender_i) { 1 } else { 0 });
        // Safe since we length-checked shares
        shares.swap_remove(relative_i)
      };
      drop(shares);

      let confirmation_nonces = handle(
        txn,
        &DataSpecification { topic: Topic::Dkg, label: DKG_CONFIRMATION_NONCES, attempt },
        confirmation_nonces.to_vec(),
        &signed,
      );
      match handle(
        txn,
        &DataSpecification { topic: Topic::Dkg, label: DKG_SHARES, attempt },
        bytes,
        &signed,
      ) {
        Some(Some(shares)) => {
          log::info!("got all DkgShares for {}", hex::encode(genesis));
          assert!(confirmation_nonces.is_some());
          processors
            .send(
              spec.set().network,
              key_gen::CoordinatorMessage::Shares {
                id: KeyGenId { set: spec.set(), attempt },
                shares,
              },
            )
            .await;
        }
        Some(None) => panic!("wasn't a participant in DKG shares"),
        None => assert!(confirmation_nonces.is_none()),
      }
    }

    Transaction::DkgConfirmed(attempt, shares, signed) => {
      match handle(
        txn,
        &DataSpecification { topic: Topic::Dkg, label: DKG_CONFIRMATION_SHARES, attempt },
        shares.to_vec(),
        &signed,
      ) {
        Some(Some(shares)) => {
          log::info!("got all DkgConfirmed for {}", hex::encode(genesis));

          let Some(preprocesses) = read_known_to_exist_data::<D, _>(
            txn,
            spec,
            key,
            &DataSpecification { topic: Topic::Dkg, label: DKG_CONFIRMATION_NONCES, attempt },
            spec.n(),
          ) else {
            panic!("wasn't a participant in DKG confirmation nonces");
          };

          let key_pair = TributaryDb::<D>::currently_completing_key_pair(txn, genesis)
            .unwrap_or_else(|| {
              panic!(
                "in DkgConfirmed handling, which happens after everyone {}",
                "(including us) fires DkgConfirmed, yet no confirming key pair"
              )
            });
          let Ok(sig) = DkgConfirmer::complete(spec, key, attempt, preprocesses, &key_pair, shares)
          else {
            // TODO: Full slash
            todo!();
          };

          publish_serai_tx(
            spec.set(),
            Serai::set_validator_set_keys(spec.set().network, key_pair, Signature(sig)),
          )
          .await;
        }
        Some(None) => panic!("wasn't a participant in DKG confirmination shares"),
        None => {}
      }
    }

    Transaction::Batch(_, batch) => {
      // Because this Batch has achieved synchrony, its batch ID should be authorized
      TributaryDb::<D>::recognize_topic(txn, genesis, Topic::Batch(batch));
      let nonce = NonceDecider::<D>::handle_batch(txn, genesis, batch);
      recognized_id(spec.set().network, genesis, RecognizedIdType::Batch, batch, nonce).await;
    }

    Transaction::SubstrateBlock(block) => {
      let plan_ids = TributaryDb::<D>::plan_ids(txn, genesis, block).expect(
        "synced a tributary block finalizing a substrate block in a provided transaction \
          despite us not providing that transaction",
      );

      let nonces = NonceDecider::<D>::handle_substrate_block(txn, genesis, &plan_ids);
      for (nonce, id) in nonces.into_iter().zip(plan_ids.into_iter()) {
        TributaryDb::<D>::recognize_topic(txn, genesis, Topic::Sign(id));
        recognized_id(spec.set().network, genesis, RecognizedIdType::Plan, id, nonce).await;
      }
    }

    Transaction::BatchPreprocess(data) => {
      match handle(
        txn,
        &DataSpecification {
          topic: Topic::Batch(data.plan),
          label: BATCH_PREPROCESS,
          attempt: data.attempt,
        },
        data.data,
        &data.signed,
      ) {
        Some(Some(preprocesses)) => {
          NonceDecider::<D>::selected_for_signing_batch(txn, genesis, data.plan);
          let key = TributaryDb::<D>::key_pair(txn, spec.set()).unwrap().0 .0.to_vec();
          processors
            .send(
              spec.set().network,
              coordinator::CoordinatorMessage::BatchPreprocesses {
                id: SignId { key, id: data.plan, attempt: data.attempt },
                preprocesses,
              },
            )
            .await;
        }
        Some(None) => {}
        None => {}
      }
    }
    Transaction::BatchShare(data) => {
      match handle(
        txn,
        &DataSpecification {
          topic: Topic::Batch(data.plan),
          label: BATCH_SHARE,
          attempt: data.attempt,
        },
        data.data,
        &data.signed,
      ) {
        Some(Some(shares)) => {
          let key = TributaryDb::<D>::key_pair(txn, spec.set()).unwrap().0 .0.to_vec();
          processors
            .send(
              spec.set().network,
              coordinator::CoordinatorMessage::BatchShares {
                id: SignId { key, id: data.plan, attempt: data.attempt },
                shares: shares
                  .into_iter()
                  .map(|(validator, share)| (validator, share.try_into().unwrap()))
                  .collect(),
              },
            )
            .await;
        }
        Some(None) => {}
        None => {}
      }
    }

    Transaction::SignPreprocess(data) => {
      let key_pair = TributaryDb::<D>::key_pair(txn, spec.set());
      match handle(
        txn,
        &DataSpecification {
          topic: Topic::Sign(data.plan),
          label: SIGN_PREPROCESS,
          attempt: data.attempt,
        },
        data.data,
        &data.signed,
      ) {
        Some(Some(preprocesses)) => {
          NonceDecider::<D>::selected_for_signing_plan(txn, genesis, data.plan);
          processors
            .send(
              spec.set().network,
              sign::CoordinatorMessage::Preprocesses {
                id: SignId {
                  key: key_pair
                    .expect("completed SignPreprocess despite not setting the key pair")
                    .1
                    .into(),
                  id: data.plan,
                  attempt: data.attempt,
                },
                preprocesses,
              },
            )
            .await;
        }
        Some(None) => {}
        None => {}
      }
    }
    Transaction::SignShare(data) => {
      let key_pair = TributaryDb::<D>::key_pair(txn, spec.set());
      match handle(
        txn,
        &DataSpecification {
          topic: Topic::Sign(data.plan),
          label: SIGN_SHARE,
          attempt: data.attempt,
        },
        data.data,
        &data.signed,
      ) {
        Some(Some(shares)) => {
          processors
            .send(
              spec.set().network,
              sign::CoordinatorMessage::Shares {
                id: SignId {
                  key: key_pair
                    .expect("completed SignShares despite not setting the key pair")
                    .1
                    .into(),
                  id: data.plan,
                  attempt: data.attempt,
                },
                shares,
              },
            )
            .await;
        }
        Some(None) => {}
        None => {}
      }
    }
    Transaction::SignCompleted { plan, tx_hash, .. } => {
      log::info!(
        "on-chain SignCompleted claims {} completes {}",
        hex::encode(&tx_hash),
        hex::encode(plan)
      );
      // TODO: Confirm this is a valid plan ID
      // TODO: Confirm this signer hasn't prior published a completion
      let Some(key_pair) = TributaryDb::<D>::key_pair(txn, spec.set()) else { todo!() };
      processors
        .send(
          spec.set().network,
          sign::CoordinatorMessage::Completed { key: key_pair.1.to_vec(), id: plan, tx: tx_hash },
        )
        .await;
    }
  }
}
