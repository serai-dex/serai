use core::{marker::PhantomData, fmt};
use std::collections::HashMap;

use rand_core::OsRng;

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

use serai_client::{
  primitives::{ExternalNetworkId, BlockHash},
  in_instructions::primitives::{Batch, SignedBatch, batch_message},
  validator_sets::primitives::Session,
};

use messages::coordinator::*;
use crate::{Get, DbTxn, Db, create_db};

create_db!(
  BatchSignerDb {
    CompletedDb: (id: u32) -> (),
    AttemptDb: (id: u32, attempt: u32) -> (),
    BatchDb: (block: BlockHash) -> SignedBatch
  }
);

type Preprocess = <AlgorithmMachine<Ristretto, Schnorrkel> as PreprocessMachine>::Preprocess;
type SignatureShare = <AlgorithmSignMachine<Ristretto, Schnorrkel> as SignMachine<
  <Schnorrkel as Algorithm<Ristretto>>::Signature,
>>::SignatureShare;

pub struct BatchSigner<D: Db> {
  db: PhantomData<D>,

  network: ExternalNetworkId,
  session: Session,
  keys: Vec<ThresholdKeys<Ristretto>>,

  signable: HashMap<u32, Batch>,
  attempt: HashMap<u32, u32>,
  #[allow(clippy::type_complexity)]
  preprocessing: HashMap<u32, (Vec<AlgorithmSignMachine<Ristretto, Schnorrkel>>, Vec<Preprocess>)>,
  #[allow(clippy::type_complexity)]
  signing: HashMap<u32, (AlgorithmSignatureMachine<Ristretto, Schnorrkel>, Vec<SignatureShare>)>,
}

impl<D: Db> fmt::Debug for BatchSigner<D> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt
      .debug_struct("BatchSigner")
      .field("signable", &self.signable)
      .field("attempt", &self.attempt)
      .finish_non_exhaustive()
  }
}

impl<D: Db> BatchSigner<D> {
  pub fn new(
    network: ExternalNetworkId,
    session: Session,
    keys: Vec<ThresholdKeys<Ristretto>>,
  ) -> BatchSigner<D> {
    assert!(!keys.is_empty());
    BatchSigner {
      db: PhantomData,

      network,
      session,
      keys,

      signable: HashMap::new(),
      attempt: HashMap::new(),
      preprocessing: HashMap::new(),
      signing: HashMap::new(),
    }
  }

  fn verify_id(&self, id: &SubstrateSignId) -> Result<(Session, u32, u32), ()> {
    let SubstrateSignId { session, id, attempt } = id;
    let SubstrateSignableId::Batch(id) = id else { panic!("BatchSigner handed non-Batch") };

    assert_eq!(session, &self.session);

    // Check the attempt lines up
    match self.attempt.get(id) {
      // If we don't have an attempt logged, it's because the coordinator is faulty OR because we
      // rebooted OR we detected the signed batch on chain
      // The latter is the expected flow for batches not actively being participated in
      None => {
        warn!("not attempting batch {id} #{attempt}");
        Err(())?;
      }
      Some(our_attempt) => {
        if attempt != our_attempt {
          warn!("sent signing data for batch {id} #{attempt} yet we have attempt #{our_attempt}");
          Err(())?;
        }
      }
    }

    Ok((*session, *id, *attempt))
  }

  #[must_use]
  fn attempt(
    &mut self,
    txn: &mut D::Transaction<'_>,
    id: u32,
    attempt: u32,
  ) -> Option<ProcessorMessage> {
    // See above commentary for why this doesn't emit SignedBatch
    if CompletedDb::get(txn, id).is_some() {
      return None;
    }

    // Check if we're already working on this attempt
    if let Some(curr_attempt) = self.attempt.get(&id) {
      if curr_attempt >= &attempt {
        warn!("told to attempt {id} #{attempt} yet we're already working on {curr_attempt}");
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

    info!("signing batch {id} #{attempt}");

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
    if AttemptDb::get(txn, id, attempt).is_some() {
      warn!(
        "already attempted batch {id}, attempt #{attempt}. this is an error if we didn't reboot"
      );
      return None;
    }
    AttemptDb::set(txn, id, attempt, &());

    let mut machines = vec![];
    let mut preprocesses = vec![];
    let mut serialized_preprocesses = vec![];
    for keys in &self.keys {
      // b"substrate" is a literal from sp-core
      let machine = AlgorithmMachine::new(Schnorrkel::new(b"substrate"), keys.clone());

      let (machine, preprocess) = machine.preprocess(&mut OsRng);
      machines.push(machine);
      serialized_preprocesses.push(preprocess.serialize().try_into().unwrap());
      preprocesses.push(preprocess);
    }
    self.preprocessing.insert(id, (machines, preprocesses));

    let id = SubstrateSignId { session: self.session, id: SubstrateSignableId::Batch(id), attempt };

    // Broadcast our preprocesses
    Some(ProcessorMessage::BatchPreprocess { id, block, preprocesses: serialized_preprocesses })
  }

  #[must_use]
  pub fn sign(&mut self, txn: &mut D::Transaction<'_>, batch: Batch) -> Option<ProcessorMessage> {
    debug_assert_eq!(self.network, batch.network);
    let id = batch.id;
    if CompletedDb::get(txn, id).is_some() {
      debug!("Sign batch order for ID we've already completed signing");
      // See batch_signed for commentary on why this simply returns
      return None;
    }

    self.signable.insert(id, batch);
    self.attempt(txn, id, 0)
  }

  #[must_use]
  pub fn handle(
    &mut self,
    txn: &mut D::Transaction<'_>,
    msg: CoordinatorMessage,
  ) -> Option<messages::ProcessorMessage> {
    match msg {
      CoordinatorMessage::CosignSubstrateBlock { .. } => {
        panic!("BatchSigner passed CosignSubstrateBlock")
      }

      CoordinatorMessage::SignSlashReport { .. } => {
        panic!("Cosigner passed SignSlashReport")
      }

      CoordinatorMessage::SubstratePreprocesses { id, preprocesses } => {
        let (session, id, attempt) = self.verify_id(&id).ok()?;

        let substrate_sign_id =
          SubstrateSignId { session, id: SubstrateSignableId::Batch(id), attempt };

        let (machines, our_preprocesses) = match self.preprocessing.remove(&id) {
          // Either rebooted or RPC error, or some invariant
          None => {
            warn!("not preprocessing for {id}. this is an error if we didn't reboot");
            return None;
          }
          Some(preprocess) => preprocess,
        };

        let mut parsed = HashMap::new();
        for l in {
          let mut keys = preprocesses.keys().copied().collect::<Vec<_>>();
          keys.sort();
          keys
        } {
          let mut preprocess_ref = preprocesses.get(&l).unwrap().as_slice();
          let Ok(res) = machines[0].read_preprocess(&mut preprocess_ref) else {
            return Some(
              (ProcessorMessage::InvalidParticipant { id: substrate_sign_id, participant: l })
                .into(),
            );
          };
          if !preprocess_ref.is_empty() {
            return Some(
              (ProcessorMessage::InvalidParticipant { id: substrate_sign_id, participant: l })
                .into(),
            );
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

          let (machine, share) = match machine
            .sign(preprocesses, &batch_message(&self.signable[&id]))
          {
            Ok(res) => res,
            Err(e) => match e {
              FrostError::InternalError(_) |
              FrostError::InvalidParticipant(_, _) |
              FrostError::InvalidSigningSet(_) |
              FrostError::InvalidParticipantQuantity(_, _) |
              FrostError::DuplicatedParticipant(_) |
              FrostError::MissingParticipant(_) => unreachable!(),

              FrostError::InvalidPreprocess(l) | FrostError::InvalidShare(l) => {
                return Some(
                  (ProcessorMessage::InvalidParticipant { id: substrate_sign_id, participant: l })
                    .into(),
                )
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
        self.signing.insert(id, (signature_machine.unwrap(), shares));

        // Broadcast our shares
        Some(
          (ProcessorMessage::SubstrateShare { id: substrate_sign_id, shares: serialized_shares })
            .into(),
        )
      }

      CoordinatorMessage::SubstrateShares { id, shares } => {
        let (session, id, attempt) = self.verify_id(&id).ok()?;

        let substrate_sign_id =
          SubstrateSignId { session, id: SubstrateSignableId::Batch(id), attempt };

        let (machine, our_shares) = match self.signing.remove(&id) {
          // Rebooted, RPC error, or some invariant
          None => {
            // If preprocessing has this ID, it means we were never sent the preprocess by the
            // coordinator
            if self.preprocessing.contains_key(&id) {
              panic!("never preprocessed yet signing?");
            }

            warn!("not preprocessing for {id}. this is an error if we didn't reboot");
            return None;
          }
          Some(signing) => signing,
        };

        let mut parsed = HashMap::new();
        for l in {
          let mut keys = shares.keys().copied().collect::<Vec<_>>();
          keys.sort();
          keys
        } {
          let mut share_ref = shares.get(&l).unwrap().as_slice();
          let Ok(res) = machine.read_share(&mut share_ref) else {
            return Some(
              (ProcessorMessage::InvalidParticipant { id: substrate_sign_id, participant: l })
                .into(),
            );
          };
          if !share_ref.is_empty() {
            return Some(
              (ProcessorMessage::InvalidParticipant { id: substrate_sign_id, participant: l })
                .into(),
            );
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
              return Some(
                (ProcessorMessage::InvalidParticipant { id: substrate_sign_id, participant: l })
                  .into(),
              )
            }
          },
        };

        info!("signed batch {id} with attempt #{attempt}");

        let batch =
          SignedBatch { batch: self.signable.remove(&id).unwrap(), signature: sig.into() };

        // Save the batch in case it's needed for recovery
        BatchDb::set(txn, batch.batch.block, &batch);
        CompletedDb::set(txn, id, &());

        // Stop trying to sign for this batch
        assert!(self.attempt.remove(&id).is_some());
        assert!(self.preprocessing.remove(&id).is_none());
        assert!(self.signing.remove(&id).is_none());

        Some((messages::substrate::ProcessorMessage::SignedBatch { batch }).into())
      }

      CoordinatorMessage::BatchReattempt { id } => {
        let SubstrateSignableId::Batch(batch_id) = id.id else {
          panic!("BatchReattempt passed non-Batch ID")
        };
        self.attempt(txn, batch_id, id.attempt).map(Into::into)
      }
    }
  }

  pub fn batch_signed(&mut self, txn: &mut D::Transaction<'_>, id: u32) {
    // Stop trying to sign for this batch
    CompletedDb::set(txn, id, &());

    self.signable.remove(&id);
    self.attempt.remove(&id);
    self.preprocessing.remove(&id);
    self.signing.remove(&id);

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
