use core::{marker::PhantomData, fmt};
use std::collections::HashMap;

use rand_core::OsRng;

use ciphersuite::group::GroupEncoding;
use frost::{
  curve::Ristretto,
  ThresholdKeys, FrostError,
  algorithm::Algorithm,
  sign::{
    Writable, PreprocessMachine, SignMachine, SignatureMachine, AlgorithmMachine,
    AlgorithmSignMachine, AlgorithmSignatureMachine,
  },
};
use frost_schnorrkel::Schnorrkel;

use log::{info, debug, warn};

use scale::Encode;
use serai_client::{
  primitives::NetworkId,
  in_instructions::primitives::{Batch, SignedBatch, batch_message},
};

use messages::coordinator::*;
use crate::{Get, DbTxn, Db};

// Generate an ID unique to a Batch
fn batch_sign_id(network: NetworkId, id: u32) -> [u8; 5] {
  (network, id).encode().try_into().unwrap()
}

#[derive(Debug)]
struct SubstrateSignerDb<D: Db>(D);
impl<D: Db> SubstrateSignerDb<D> {
  fn sign_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"SUBSTRATE_SIGNER", dst, key)
  }

  fn completed_key(id: [u8; 5]) -> Vec<u8> {
    Self::sign_key(b"completed", id)
  }
  fn complete(txn: &mut D::Transaction<'_>, id: [u8; 5]) {
    txn.put(Self::completed_key(id), []);
  }
  fn completed<G: Get>(getter: &G, id: [u8; 5]) -> bool {
    getter.get(Self::completed_key(id)).is_some()
  }

  fn attempt_key(id: &BatchSignId) -> Vec<u8> {
    Self::sign_key(b"attempt", id.encode())
  }
  fn attempt(txn: &mut D::Transaction<'_>, id: &BatchSignId) {
    txn.put(Self::attempt_key(id), []);
  }
  fn has_attempt<G: Get>(getter: &G, id: &BatchSignId) -> bool {
    getter.get(Self::attempt_key(id)).is_some()
  }

  fn save_batch(txn: &mut D::Transaction<'_>, batch: &SignedBatch) {
    txn.put(Self::sign_key(b"batch", batch.batch.block), batch.encode());
  }
}

type Preprocess = <AlgorithmMachine<Ristretto, Schnorrkel> as PreprocessMachine>::Preprocess;
type SignatureShare = <AlgorithmSignMachine<Ristretto, Schnorrkel> as SignMachine<
  <Schnorrkel as Algorithm<Ristretto>>::Signature,
>>::SignatureShare;

pub struct SubstrateSigner<D: Db> {
  db: PhantomData<D>,

  network: NetworkId,
  keys: Vec<ThresholdKeys<Ristretto>>,

  signable: HashMap<[u8; 5], Batch>,
  attempt: HashMap<[u8; 5], u32>,
  #[allow(clippy::type_complexity)]
  preprocessing:
    HashMap<[u8; 5], (Vec<AlgorithmSignMachine<Ristretto, Schnorrkel>>, Vec<Preprocess>)>,
  #[allow(clippy::type_complexity)]
  signing:
    HashMap<[u8; 5], (AlgorithmSignatureMachine<Ristretto, Schnorrkel>, Vec<SignatureShare>)>,
}

impl<D: Db> fmt::Debug for SubstrateSigner<D> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt
      .debug_struct("SubstrateSigner")
      .field("signable", &self.signable)
      .field("attempt", &self.attempt)
      .finish_non_exhaustive()
  }
}

impl<D: Db> SubstrateSigner<D> {
  pub fn new(network: NetworkId, keys: Vec<ThresholdKeys<Ristretto>>) -> SubstrateSigner<D> {
    assert!(!keys.is_empty());
    SubstrateSigner {
      db: PhantomData,

      network,
      keys,

      signable: HashMap::new(),
      attempt: HashMap::new(),
      preprocessing: HashMap::new(),
      signing: HashMap::new(),
    }
  }

  fn verify_id(&self, id: &BatchSignId) -> Result<(), ()> {
    // Check the attempt lines up
    match self.attempt.get(&id.id) {
      // If we don't have an attempt logged, it's because the coordinator is faulty OR because we
      // rebooted OR we detected the signed batch on chain
      // The latter is the expected flow for batches not actively being participated in
      None => {
        warn!("not attempting batch {} #{}", hex::encode(id.id), id.attempt);
        Err(())?;
      }
      Some(attempt) => {
        if attempt != &id.attempt {
          warn!(
            "sent signing data for batch {} #{} yet we have attempt #{}",
            hex::encode(id.id),
            id.attempt,
            attempt
          );
          Err(())?;
        }
      }
    }

    Ok(())
  }

  #[must_use]
  async fn attempt(
    &mut self,
    txn: &mut D::Transaction<'_>,
    id: [u8; 5],
    attempt: u32,
  ) -> Option<ProcessorMessage> {
    // See above commentary for why this doesn't emit SignedBatch
    if SubstrateSignerDb::<D>::completed(txn, id) {
      return None;
    }

    // Check if we're already working on this attempt
    if let Some(curr_attempt) = self.attempt.get(&id) {
      if curr_attempt >= &attempt {
        warn!(
          "told to attempt {} #{} yet we're already working on {}",
          hex::encode(id),
          attempt,
          curr_attempt
        );
        return None;
      }
    }

    // Start this attempt
    let block = if let Some(batch) = self.signable.get(&id) {
      batch.block
    } else {
      warn!("told to attempt signing a batch we aren't currently signing for");
      return None;
    };

    // Delete any existing machines
    self.preprocessing.remove(&id);
    self.signing.remove(&id);

    // Update the attempt number
    self.attempt.insert(id, attempt);

    let id = BatchSignId { key: self.keys[0].group_key().to_bytes(), id, attempt };
    info!("signing batch {} #{}", hex::encode(id.id), id.attempt);

    // If we reboot mid-sign, the current design has us abort all signs and wait for latter
    // attempts/new signing protocols
    // This is distinct from the DKG which will continue DKG sessions, even on reboot
    // This is because signing is tolerant of failures of up to 1/3rd of the group
    // The DKG requires 100% participation
    // While we could apply similar tricks as the DKG (a seeded RNG) to achieve support for
    // reboots, it's not worth the complexity when messing up here leaks our secret share
    //
    // Despite this, on reboot, we'll get told of active signing items, and may be in this
    // branch again for something we've already attempted
    //
    // Only run if this hasn't already been attempted
    // TODO: This isn't complete as this txn may not be committed with the expected timing
    if SubstrateSignerDb::<D>::has_attempt(txn, &id) {
      warn!(
        "already attempted batch {}, attempt #{}. this is an error if we didn't reboot",
        hex::encode(id.id),
        id.attempt
      );
      return None;
    }

    SubstrateSignerDb::<D>::attempt(txn, &id);

    let mut machines = vec![];
    let mut preprocesses = vec![];
    let mut serialized_preprocesses = vec![];
    for keys in &self.keys {
      // b"substrate" is a literal from sp-core
      let machine = AlgorithmMachine::new(Schnorrkel::new(b"substrate"), keys.clone());

      let (machine, preprocess) = machine.preprocess(&mut OsRng);
      machines.push(machine);
      serialized_preprocesses.push(preprocess.serialize());
      preprocesses.push(preprocess);
    }
    self.preprocessing.insert(id.id, (machines, preprocesses));

    // Broadcast our preprocesses
    Some(ProcessorMessage::BatchPreprocess { id, block, preprocesses: serialized_preprocesses })
  }

  #[must_use]
  pub async fn sign(
    &mut self,
    txn: &mut D::Transaction<'_>,
    batch: Batch,
  ) -> Option<ProcessorMessage> {
    debug_assert_eq!(self.network, batch.network);
    let id = batch_sign_id(batch.network, batch.id);
    if SubstrateSignerDb::<D>::completed(txn, id) {
      debug!("Sign batch order for ID we've already completed signing");
      // See batch_signed for commentary on why this simply returns
      return None;
    }

    self.signable.insert(id, batch);
    self.attempt(txn, id, 0).await
  }

  #[must_use]
  pub async fn handle(
    &mut self,
    txn: &mut D::Transaction<'_>,
    msg: CoordinatorMessage,
  ) -> Option<messages::ProcessorMessage> {
    match msg {
      CoordinatorMessage::BatchPreprocesses { id, preprocesses } => {
        if self.verify_id(&id).is_err() {
          return None;
        }

        let (machines, our_preprocesses) = match self.preprocessing.remove(&id.id) {
          // Either rebooted or RPC error, or some invariant
          None => {
            warn!(
              "not preprocessing for {}. this is an error if we didn't reboot",
              hex::encode(id.id),
            );
            return None;
          }
          Some(preprocess) => preprocess,
        };

        let mut parsed = HashMap::new();
        for l in {
          let mut keys = preprocesses.keys().cloned().collect::<Vec<_>>();
          keys.sort();
          keys
        } {
          let mut preprocess_ref = preprocesses.get(&l).unwrap().as_slice();
          let Ok(res) = machines[0].read_preprocess(&mut preprocess_ref) else {
            return Some((ProcessorMessage::InvalidParticipant { id, participant: l }).into());
          };
          if !preprocess_ref.is_empty() {
            return Some((ProcessorMessage::InvalidParticipant { id, participant: l }).into());
          }
          parsed.insert(l, res);
        }
        let preprocesses = parsed;

        // Only keep a single machine as we only need one to get the signature
        let mut signature_machine = None;
        let mut shares = vec![];
        let mut serialized_shares = vec![];
        for (m, machine) in machines.into_iter().enumerate() {
          let mut preprocesses = preprocesses.clone();
          for (i, our_preprocess) in our_preprocesses.clone().into_iter().enumerate() {
            if i != m {
              assert!(preprocesses.insert(self.keys[i].params().i(), our_preprocess).is_none());
            }
          }

          let (machine, share) =
            match machine.sign(preprocesses, &batch_message(&self.signable[&id.id])) {
              Ok(res) => res,
              Err(e) => match e {
                FrostError::InternalError(_) |
                FrostError::InvalidParticipant(_, _) |
                FrostError::InvalidSigningSet(_) |
                FrostError::InvalidParticipantQuantity(_, _) |
                FrostError::DuplicatedParticipant(_) |
                FrostError::MissingParticipant(_) => unreachable!(),

                FrostError::InvalidPreprocess(l) | FrostError::InvalidShare(l) => {
                  return Some((ProcessorMessage::InvalidParticipant { id, participant: l }).into())
                }
              },
            };
          if m == 0 {
            signature_machine = Some(machine);
          }

          let mut share_bytes = [0; 32];
          share_bytes.copy_from_slice(&share.serialize());
          serialized_shares.push(share_bytes);

          shares.push(share);
        }
        self.signing.insert(id.id, (signature_machine.unwrap(), shares));

        // Broadcast our shares
        Some((ProcessorMessage::BatchShare { id, shares: serialized_shares }).into())
      }

      CoordinatorMessage::BatchShares { id, shares } => {
        if self.verify_id(&id).is_err() {
          return None;
        }

        let (machine, our_shares) = match self.signing.remove(&id.id) {
          // Rebooted, RPC error, or some invariant
          None => {
            // If preprocessing has this ID, it means we were never sent the preprocess by the
            // coordinator
            if self.preprocessing.contains_key(&id.id) {
              panic!("never preprocessed yet signing?");
            }

            warn!(
              "not preprocessing for {}. this is an error if we didn't reboot",
              hex::encode(id.id)
            );
            return None;
          }
          Some(signing) => signing,
        };

        let mut parsed = HashMap::new();
        for l in {
          let mut keys = shares.keys().cloned().collect::<Vec<_>>();
          keys.sort();
          keys
        } {
          let mut share_ref = shares.get(&l).unwrap().as_slice();
          let Ok(res) = machine.read_share(&mut share_ref) else {
            return Some((ProcessorMessage::InvalidParticipant { id, participant: l }).into());
          };
          if !share_ref.is_empty() {
            return Some((ProcessorMessage::InvalidParticipant { id, participant: l }).into());
          }
          parsed.insert(l, res);
        }
        let mut shares = parsed;

        for (i, our_share) in our_shares.into_iter().enumerate().skip(1) {
          assert!(shares.insert(self.keys[i].params().i(), our_share).is_none());
        }

        let sig = match machine.complete(shares) {
          Ok(res) => res,
          Err(e) => match e {
            FrostError::InternalError(_) |
            FrostError::InvalidParticipant(_, _) |
            FrostError::InvalidSigningSet(_) |
            FrostError::InvalidParticipantQuantity(_, _) |
            FrostError::DuplicatedParticipant(_) |
            FrostError::MissingParticipant(_) => unreachable!(),

            FrostError::InvalidPreprocess(l) | FrostError::InvalidShare(l) => {
              return Some((ProcessorMessage::InvalidParticipant { id, participant: l }).into())
            }
          },
        };

        info!("signed batch {} with attempt #{}", hex::encode(id.id), id.attempt);

        let batch =
          SignedBatch { batch: self.signable.remove(&id.id).unwrap(), signature: sig.into() };

        // Save the batch in case it's needed for recovery
        SubstrateSignerDb::<D>::save_batch(txn, &batch);
        SubstrateSignerDb::<D>::complete(txn, id.id);

        // Stop trying to sign for this batch
        assert!(self.attempt.remove(&id.id).is_some());
        assert!(self.preprocessing.remove(&id.id).is_none());
        assert!(self.signing.remove(&id.id).is_none());

        Some((messages::substrate::ProcessorMessage::SignedBatch { batch }).into())
      }

      CoordinatorMessage::BatchReattempt { id } => {
        self.attempt(txn, id.id, id.attempt).await.map(Into::into)
      }
    }
  }

  pub fn batch_signed(&mut self, txn: &mut D::Transaction<'_>, id: u32) {
    let sign_id = batch_sign_id(self.network, id);

    // Stop trying to sign for this batch
    SubstrateSignerDb::<D>::complete(txn, sign_id);

    self.signable.remove(&sign_id);
    self.attempt.remove(&sign_id);
    self.preprocessing.remove(&sign_id);
    self.signing.remove(&sign_id);

    // This doesn't emit SignedBatch because it doesn't have access to the SignedBatch
    // This function is expected to only be called once Substrate acknowledges this block,
    // which means its batch must have been signed
    // While a successive batch's signing would also cause this block to be acknowledged, Substrate
    // guarantees a batch's ordered inclusion

    // This also doesn't return any messages since all mutation from the Batch being signed happens
    // on the substrate::CoordinatorMessage::SubstrateBlock message (which SignedBatch is meant to
    // end up triggering)
  }
}
