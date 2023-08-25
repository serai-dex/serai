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
  primitives::NetworkId,
  validator_sets::primitives::{ValidatorSet, KeyPair, musig_context, set_keys_message},
  subxt::utils::Encoded,
  Serai,
};

use tributary::Signed;

use processor_messages::{
  CoordinatorMessage, coordinator,
  key_gen::{self, KeyGenId},
  sign::{self, SignId},
};

use serai_db::{Get, Db};

use crate::processors::Processors;
use super::{Transaction, TributarySpec, TributaryDb, scanner::RecognizedIdType};

const DKG_CONFIRMATION_NONCES: &[u8] = b"dkg_confirmation_nonces";
const DKG_CONFIRMATION_SHARES: &[u8] = b"dkg_confirmation_shares";

// Instead of maintaing state, this simply re-creates the machine(s) in-full on every call.
// This simplifies data flow and prevents requiring multiple paths.
// While more expensive, this only runs an O(n) algorithm, which is tolerable to run multiple
// times.
struct DkgConfirmer;
impl DkgConfirmer {
  fn preprocess_internal(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  ) -> (AlgorithmSignMachine<Ristretto, Schnorrkel>, [u8; 64]) {
    // TODO: Does Substrate already have a validator-uniqueness check?
    let validators = spec.validators().iter().map(|val| val.0).collect::<Vec<_>>();

    let context = musig_context(spec.set());
    let mut chacha = ChaCha20Rng::from_seed({
      let mut entropy_transcript = RecommendedTranscript::new(b"DkgConfirmer Entropy");
      entropy_transcript.append_message(b"spec", spec.serialize());
      entropy_transcript.append_message(b"key", Zeroizing::new(key.to_bytes()));
      // TODO: This is incredibly insecure unless message-bound (or bound via the attempt)
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
  fn preprocess(spec: &TributarySpec, key: &Zeroizing<<Ristretto as Ciphersuite>::F>) -> [u8; 64] {
    Self::preprocess_internal(spec, key).1
  }

  fn share_internal(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
  ) -> Result<(AlgorithmSignatureMachine<Ristretto, Schnorrkel>, [u8; 32]), Participant> {
    let machine = Self::preprocess_internal(spec, key).0;
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
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
  ) -> Result<[u8; 32], Participant> {
    Self::share_internal(spec, key, preprocesses, key_pair).map(|(_, share)| share)
  }

  fn complete(
    spec: &TributarySpec,
    key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
    shares: HashMap<Participant, Vec<u8>>,
  ) -> Result<[u8; 64], Participant> {
    let machine = Self::share_internal(spec, key, preprocesses, key_pair)
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

#[allow(clippy::too_many_arguments)] // TODO
fn read_known_to_exist_data<D: Db, G: Get>(
  getter: &G,
  spec: &TributarySpec,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  label: &'static [u8],
  id: [u8; 32],
  needed: u16,
  attempt: u32,
  bytes: Vec<u8>,
  signed: Option<&Signed>,
) -> HashMap<Participant, Vec<u8>> {
  let mut data = HashMap::new();
  for validator in spec.validators().iter().map(|validator| validator.0) {
    data.insert(
      spec.i(validator).unwrap(),
      if Some(&validator) == signed.map(|signed| &signed.signer) {
        bytes.clone()
      } else if let Some(data) =
        TributaryDb::<D>::data(label, getter, spec.genesis(), id, attempt, validator)
      {
        data
      } else {
        continue;
      },
    );
  }
  assert_eq!(data.len(), usize::from(needed));

  // Remove our own piece of data
  assert!(data
    .remove(
      &spec
        .i(Ristretto::generator() * key.deref())
        .expect("handling a message for a Tributary we aren't part of")
    )
    .is_some());

  data
}

pub fn dkg_confirmation_nonces(
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  spec: &TributarySpec,
) -> [u8; 64] {
  DkgConfirmer::preprocess(spec, key)
}

#[allow(clippy::needless_pass_by_ref_mut)]
pub fn generated_key_pair<D: Db>(
  txn: &mut D::Transaction<'_>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  spec: &TributarySpec,
  key_pair: &KeyPair,
) -> Result<[u8; 32], Participant> {
  TributaryDb::<D>::save_currently_completing_key_pair(txn, spec.genesis(), key_pair);

  let attempt = 0; // TODO
  let preprocesses = read_known_to_exist_data::<D, _>(
    txn,
    spec,
    key,
    DKG_CONFIRMATION_NONCES,
    [0; 32],
    spec.n(),
    attempt,
    vec![],
    None,
  );
  DkgConfirmer::share(spec, key, preprocesses, key_pair)
}

#[allow(clippy::too_many_arguments)] // TODO
pub async fn handle_application_tx<
  D: Db,
  Pro: Processors,
  FPst: Future<Output = ()>,
  PST: Clone + Fn(ValidatorSet, Encoded) -> FPst,
  FRid: Future<Output = Vec<[u8; 32]>>,
  RID: Clone + Fn(NetworkId, [u8; 32], RecognizedIdType, [u8; 32]) -> FRid,
>(
  tx: Transaction,
  spec: &TributarySpec,
  processors: &Pro,
  publish_serai_tx: PST,
  genesis: [u8; 32],
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: RID,
  txn: &mut <D as Db>::Transaction<'_>,
) {
  // Used to determine if an ID is acceptable
  #[derive(Clone, Copy, PartialEq, Eq, Debug)]
  enum Zone {
    Dkg,
    Batch,
    Sign,
  }

  impl Zone {
    fn label(&self) -> &'static str {
      match self {
        Zone::Dkg => {
          panic!("getting the label for dkg despite dkg code paths not needing a label")
        }
        Zone::Batch => "batch",
        Zone::Sign => "sign",
      }
    }
  }

  let handle =
    |txn: &mut _, zone: Zone, label, needed, id, attempt, bytes: Vec<u8>, signed: &Signed| {
      if zone == Zone::Dkg {
        // Since Dkg doesn't have an ID, solely attempts, this should just be [0; 32]
        assert_eq!(id, [0; 32], "DKG, which shouldn't have IDs, had a non-0 ID");
      } else if !TributaryDb::<D>::recognized_id(txn, zone.label(), genesis, id) {
        // TODO: Full slash
        todo!();
      }

      // If they've already published a TX for this attempt, slash
      if let Some(data) = TributaryDb::<D>::data(label, txn, genesis, id, attempt, signed.signer) {
        if data != bytes {
          // TODO: Full slash
          todo!();
        }

        // TODO: Slash
        return None;
      }

      // If the attempt is lesser than the blockchain's, slash
      let curr_attempt = TributaryDb::<D>::attempt(txn, genesis, id);
      if attempt < curr_attempt {
        // TODO: Slash for being late
        return None;
      }
      if attempt > curr_attempt {
        // TODO: Full slash
        todo!();
      }

      // TODO: We can also full slash if shares before all commitments, or share before the
      // necessary preprocesses

      // TODO: If this is shares, we need to check they are part of the selected signing set

      // Store this data
      let received =
        TributaryDb::<D>::set_data(label, txn, genesis, id, attempt, signed.signer, &bytes);

      // If we have all the needed commitments/preprocesses/shares, tell the processor
      // TODO: This needs to be coded by weight, not by validator count
      if received == needed {
        return Some(read_known_to_exist_data::<D, _>(
          txn,
          spec,
          key,
          label,
          id,
          needed,
          attempt,
          bytes,
          Some(signed),
        ));
      }
      None
    };

  match tx {
    Transaction::DkgCommitments(attempt, bytes, signed) => {
      if let Some(commitments) =
        handle(txn, Zone::Dkg, b"dkg_commitments", spec.n(), [0; 32], attempt, bytes, &signed)
      {
        log::info!("got all DkgCommitments for {}", hex::encode(genesis));
        processors
          .send(
            spec.set().network,
            CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Commitments {
              id: KeyGenId { set: spec.set(), attempt },
              commitments,
            }),
          )
          .await;
      }
    }

    Transaction::DkgShares { attempt, sender_i, mut shares, confirmation_nonces, signed } => {
      if sender_i !=
        spec
          .i(signed.signer)
          .expect("transaction added to tributary by signer who isn't a participant")
      {
        // TODO: Full slash
        todo!();
      }

      if shares.len() != (usize::from(spec.n()) - 1) {
        // TODO: Full slash
        todo!();
      }

      // Only save our share's bytes
      let our_i = spec
        .i(Ristretto::generator() * key.deref())
        .expect("in a tributary we're not a validator for");
      // This unwrap is safe since the length of shares is checked, the the only missing key
      // within the valid range will be the sender's i
      let bytes = if sender_i == our_i { vec![] } else { shares.remove(&our_i).unwrap() };

      let confirmation_nonces = handle(
        txn,
        Zone::Dkg,
        DKG_CONFIRMATION_NONCES,
        spec.n(),
        [0; 32],
        attempt,
        confirmation_nonces.to_vec(),
        &signed,
      );
      if let Some(shares) =
        handle(txn, Zone::Dkg, b"dkg_shares", spec.n(), [0; 32], attempt, bytes, &signed)
      {
        log::info!("got all DkgShares for {}", hex::encode(genesis));
        assert!(confirmation_nonces.is_some());
        processors
          .send(
            spec.set().network,
            CoordinatorMessage::KeyGen(key_gen::CoordinatorMessage::Shares {
              id: KeyGenId { set: spec.set(), attempt },
              shares,
            }),
          )
          .await;
      } else {
        assert!(confirmation_nonces.is_none());
      }
    }

    Transaction::DkgConfirmed(attempt, shares, signed) => {
      if let Some(shares) = handle(
        txn,
        Zone::Dkg,
        DKG_CONFIRMATION_SHARES,
        spec.n(),
        [0; 32],
        attempt,
        shares.to_vec(),
        &signed,
      ) {
        log::info!("got all DkgConfirmed for {}", hex::encode(genesis));

        let preprocesses = read_known_to_exist_data::<D, _>(
          txn,
          spec,
          key,
          DKG_CONFIRMATION_NONCES,
          [0; 32],
          spec.n(),
          attempt,
          vec![],
          None,
        );

        let key_pair = TributaryDb::<D>::currently_completing_key_pair(txn, genesis)
          .unwrap_or_else(|| {
            panic!(
              "in DkgConfirmed handling, which happens after everyone {}",
              "(including us) fires DkgConfirmed, yet no confirming key pair"
            )
          });
        let Ok(sig) = DkgConfirmer::complete(spec, key, preprocesses, &key_pair, shares) else {
          // TODO: Full slash
          todo!();
        };

        publish_serai_tx(
          spec.set(),
          Serai::set_validator_set_keys(spec.set().network, key_pair, Signature(sig)),
        )
        .await;
      }
    }

    Transaction::ExternalBlock(block) => {
      // Because this external block has been finalized, its batch IDs should be authorized
      for id in recognized_id(spec.set().network, genesis, RecognizedIdType::Block, block).await {
        TributaryDb::<D>::recognize_id(txn, Zone::Batch.label(), genesis, id);
      }
    }

    Transaction::SubstrateBlock(block) => {
      let plan_ids = TributaryDb::<D>::plan_ids(txn, genesis, block).expect(
        "synced a tributary block finalizing a substrate block in a provided transaction \
          despite us not providing that transaction",
      );

      for id in plan_ids {
        TributaryDb::<D>::recognize_id(txn, Zone::Sign.label(), genesis, id);
        assert_eq!(
          recognized_id(spec.set().network, genesis, RecognizedIdType::Plan, id).await,
          vec![id]
        );
      }
    }

    Transaction::BatchPreprocess(data) => {
      if let Some(preprocesses) = handle(
        txn,
        Zone::Batch,
        b"batch_preprocess",
        spec.t(),
        data.plan,
        data.attempt,
        data.data,
        &data.signed,
      ) {
        processors
          .send(
            spec.set().network,
            CoordinatorMessage::Coordinator(coordinator::CoordinatorMessage::BatchPreprocesses {
              id: SignId { key: vec![], id: data.plan, attempt: data.attempt },
              preprocesses,
            }),
          )
          .await;
      }
    }
    Transaction::BatchShare(data) => {
      if let Some(shares) = handle(
        txn,
        Zone::Batch,
        b"batch_share",
        spec.t(),
        data.plan,
        data.attempt,
        data.data,
        &data.signed,
      ) {
        processors
          .send(
            spec.set().network,
            CoordinatorMessage::Coordinator(coordinator::CoordinatorMessage::BatchShares {
              id: SignId { key: vec![], id: data.plan, attempt: data.attempt },
              shares: shares
                .into_iter()
                .map(|(validator, share)| (validator, share.try_into().unwrap()))
                .collect(),
            }),
          )
          .await;
      }
    }

    Transaction::SignPreprocess(data) => {
      if let Some(preprocesses) = handle(
        txn,
        Zone::Sign,
        b"sign_preprocess",
        spec.t(),
        data.plan,
        data.attempt,
        data.data,
        &data.signed,
      ) {
        processors
          .send(
            spec.set().network,
            CoordinatorMessage::Sign(sign::CoordinatorMessage::Preprocesses {
              id: SignId { key: todo!(), id: data.plan, attempt: data.attempt },
              preprocesses,
            }),
          )
          .await;
      }
    }
    Transaction::SignShare(data) => {
      if let Some(shares) = handle(
        txn,
        Zone::Sign,
        b"sign_share",
        spec.t(),
        data.plan,
        data.attempt,
        data.data,
        &data.signed,
      ) {
        processors
          .send(
            spec.set().network,
            CoordinatorMessage::Sign(sign::CoordinatorMessage::Shares {
              id: SignId { key: todo!(), id: data.plan, attempt: data.attempt },
              shares,
            }),
          )
          .await;
      }
    }
    Transaction::SignCompleted(_, _, _) => todo!(),
  }
}
