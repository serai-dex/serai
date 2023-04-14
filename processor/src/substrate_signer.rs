use core::fmt;
use std::{
  sync::Arc,
  time::{SystemTime, Duration},
  collections::HashMap,
};

use rand_core::OsRng;

use scale::Encode;

use group::GroupEncoding;
use frost::{
  curve::Ristretto,
  ThresholdKeys,
  sign::{
    Writable, PreprocessMachine, SignMachine, SignatureMachine, AlgorithmMachine,
    AlgorithmSignMachine, AlgorithmSignatureMachine,
  },
};
use frost_schnorrkel::Schnorrkel;

use log::{info, debug, warn};
use tokio::{
  sync::{RwLock, mpsc},
  time::sleep,
};

use serai_client::in_instructions::primitives::{Batch, SignedBatch};

use messages::{sign::SignId, coordinator::*};
use crate::{DbTxn, Db};

const CHANNEL_MSG: &str = "SubstrateSigner handler was dropped. Shutting down?";

#[derive(Debug)]
pub enum SubstrateSignerEvent {
  ProcessorMessage(ProcessorMessage),
  SignedBatch(SignedBatch),
}

pub type SubstrateSignerEventChannel = mpsc::UnboundedReceiver<SubstrateSignerEvent>;

#[derive(Debug)]
struct SubstrateSignerDb<D: Db>(D);
impl<D: Db> SubstrateSignerDb<D> {
  fn sign_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"SUBSTRATE_SIGNER", dst, key)
  }

  fn completed_key(id: [u8; 32]) -> Vec<u8> {
    Self::sign_key(b"completed", id)
  }
  fn complete(txn: &mut D::Transaction<'_>, id: [u8; 32]) {
    txn.put(Self::completed_key(id), [1]);
  }
  fn completed(&self, id: [u8; 32]) -> bool {
    self.0.get(Self::completed_key(id)).is_some()
  }

  fn attempt_key(id: &SignId) -> Vec<u8> {
    Self::sign_key(b"attempt", bincode::serialize(id).unwrap())
  }
  fn attempt(txn: &mut D::Transaction<'_>, id: &SignId) {
    txn.put(Self::attempt_key(id), []);
  }
  fn has_attempt(&mut self, id: &SignId) -> bool {
    self.0.get(Self::attempt_key(id)).is_some()
  }

  fn save_batch(txn: &mut D::Transaction<'_>, batch: &SignedBatch) {
    txn.put(Self::sign_key(b"batch", batch.batch.block), batch.encode());
  }
}

pub struct SubstrateSigner<D: Db> {
  db: SubstrateSignerDb<D>,

  keys: ThresholdKeys<Ristretto>,

  signable: HashMap<[u8; 32], (SystemTime, Batch)>,
  attempt: HashMap<[u8; 32], u32>,
  preprocessing: HashMap<[u8; 32], AlgorithmSignMachine<Ristretto, Schnorrkel>>,
  signing: HashMap<[u8; 32], AlgorithmSignatureMachine<Ristretto, Schnorrkel>>,

  events: mpsc::UnboundedSender<SubstrateSignerEvent>,
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

#[derive(Debug)]
pub struct SubstrateSignerHandle<D: Db> {
  signer: Arc<RwLock<SubstrateSigner<D>>>,
  pub events: SubstrateSignerEventChannel,
}

impl<D: Db> SubstrateSigner<D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(db: D, keys: ThresholdKeys<Ristretto>) -> SubstrateSignerHandle<D> {
    let (events_send, events_recv) = mpsc::unbounded_channel();

    let signer = Arc::new(RwLock::new(SubstrateSigner {
      db: SubstrateSignerDb(db),

      keys,

      signable: HashMap::new(),
      attempt: HashMap::new(),
      preprocessing: HashMap::new(),
      signing: HashMap::new(),

      events: events_send,
    }));

    tokio::spawn(SubstrateSigner::run(signer.clone()));

    SubstrateSignerHandle { signer, events: events_recv }
  }

  fn verify_id(&self, id: &SignId) -> Result<(), ()> {
    if !id.signing_set(&self.keys.params()).contains(&self.keys.params().i()) {
      panic!("coordinator sent us preprocesses for a signing attempt we're not participating in");
    }

    // Check the attempt lines up
    match self.attempt.get(&id.id) {
      // If we don't have an attempt logged, it's because the coordinator is faulty OR
      // because we rebooted
      None => {
        warn!("not attempting {}. this is an error if we didn't reboot", hex::encode(id.id));
        // Don't panic on the assumption we rebooted
        Err(())?;
      }
      Some(attempt) => {
        // This could be an old attempt, or it may be a 'future' attempt if we rebooted and
        // our SystemTime wasn't monotonic, as it may be
        if attempt != &id.attempt {
          debug!("sent signing data for a distinct attempt");
          Err(())?;
        }
      }
    }

    Ok(())
  }

  fn emit(&mut self, event: SubstrateSignerEvent) -> bool {
    if self.events.send(event).is_err() {
      info!("{}", CHANNEL_MSG);
      false
    } else {
      true
    }
  }

  async fn handle(&mut self, msg: CoordinatorMessage) {
    match msg {
      CoordinatorMessage::BatchPreprocesses { id, mut preprocesses } => {
        if self.verify_id(&id).is_err() {
          return;
        }

        let machine = match self.preprocessing.remove(&id.id) {
          // Either rebooted or RPC error, or some invariant
          None => {
            warn!(
              "not preprocessing for {}. this is an error if we didn't reboot",
              hex::encode(id.id)
            );
            return;
          }
          Some(machine) => machine,
        };

        let preprocesses = match preprocesses
          .drain()
          .map(|(l, preprocess)| {
            machine
              .read_preprocess::<&[u8]>(&mut preprocess.as_ref())
              .map(|preprocess| (l, preprocess))
          })
          .collect::<Result<_, _>>()
        {
          Ok(preprocesses) => preprocesses,
          Err(e) => todo!("malicious signer: {:?}", e),
        };

        let (machine, share) = match machine.sign(preprocesses, &self.signable[&id.id].1.encode()) {
          Ok(res) => res,
          Err(e) => todo!("malicious signer: {:?}", e),
        };
        self.signing.insert(id.id, machine);

        // Broadcast our share
        let mut share_bytes = [0; 32];
        share_bytes.copy_from_slice(&share.serialize());
        self.emit(SubstrateSignerEvent::ProcessorMessage(ProcessorMessage::BatchShare {
          id,
          share: share_bytes,
        }));
      }

      CoordinatorMessage::BatchShares { id, mut shares } => {
        if self.verify_id(&id).is_err() {
          return;
        }

        let machine = match self.signing.remove(&id.id) {
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
            return;
          }
          Some(machine) => machine,
        };

        let shares = match shares
          .drain()
          .map(|(l, share)| {
            machine.read_share::<&[u8]>(&mut share.as_ref()).map(|share| (l, share))
          })
          .collect::<Result<_, _>>()
        {
          Ok(shares) => shares,
          Err(e) => todo!("malicious signer: {:?}", e),
        };

        let sig = match machine.complete(shares) {
          Ok(res) => res,
          Err(e) => todo!("malicious signer: {:?}", e),
        };

        let batch =
          SignedBatch { batch: self.signable.remove(&id.id).unwrap().1, signature: sig.into() };

        // Save the batch in case it's needed for recovery
        let mut txn = self.db.0.txn();
        SubstrateSignerDb::<D>::save_batch(&mut txn, &batch);
        SubstrateSignerDb::<D>::complete(&mut txn, id.id);
        txn.commit();

        // Stop trying to sign for this batch
        assert!(self.attempt.remove(&id.id).is_some());
        assert!(self.preprocessing.remove(&id.id).is_none());
        assert!(self.signing.remove(&id.id).is_none());

        self.emit(SubstrateSignerEvent::SignedBatch(batch));
      }

      CoordinatorMessage::BatchSigned { key: _, block } => {
        // Stop trying to sign for this batch
        let mut txn = self.db.0.txn();
        SubstrateSignerDb::<D>::complete(&mut txn, block.0);
        txn.commit();

        self.signable.remove(&block.0);
        self.attempt.remove(&block.0);
        self.preprocessing.remove(&block.0);
        self.signing.remove(&block.0);

        // This doesn't emit SignedBatch because it doesn't have access to the SignedBatch
        // The coordinator is expected to only claim a batch was signed if it's on the Substrate
        // chain, hence why it's unnecessary to check it/back it up here

        // This also doesn't emit any further events since all mutation happen on the
        // substrate::CoordinatorMessage::BlockAcknowledged message (which SignedBatch is meant to
        // end up triggering)
      }
    }
  }

  // An async function, to be spawned on a task, to handle signing
  async fn run(signer_arc: Arc<RwLock<Self>>) {
    const SIGN_TIMEOUT: u64 = 30;

    loop {
      // Sleep until a timeout expires (or five seconds expire)
      // Since this code start new sessions, it will delay any ordered signing sessions from
      // starting for up to 5 seconds, hence why this number can't be too high (such as 30 seconds,
      // the full timeout)
      // This won't delay re-attempting any signing session however, nor will it block the
      // sign_transaction function (since this doesn't hold any locks)
      sleep({
        let now = SystemTime::now();
        let mut lowest = Duration::from_secs(5);
        let signer = signer_arc.read().await;
        for (id, (start, _)) in &signer.signable {
          let until = if let Some(attempt) = signer.attempt.get(id) {
            // Get when this attempt times out
            (*start + Duration::from_secs(u64::from(attempt + 1) * SIGN_TIMEOUT))
              .duration_since(now)
              .unwrap_or(Duration::ZERO)
          } else {
            Duration::ZERO
          };

          if until < lowest {
            lowest = until;
          }
        }
        lowest
      })
      .await;

      // Because a signing attempt has timed out (or five seconds has passed), check all
      // sessions' timeouts
      {
        let mut signer = signer_arc.write().await;
        let keys = signer.signable.keys().cloned().collect::<Vec<_>>();
        for id in keys {
          let (start, _) = &signer.signable[&id];
          let start = *start;

          let attempt = u32::try_from(
            SystemTime::now().duration_since(start).unwrap_or(Duration::ZERO).as_secs() /
              SIGN_TIMEOUT,
          )
          .unwrap();

          // Check if we're already working on this attempt
          if let Some(curr_attempt) = signer.attempt.get(&id) {
            if curr_attempt >= &attempt {
              continue;
            }
          }

          // Delete any existing machines
          signer.preprocessing.remove(&id);
          signer.signing.remove(&id);

          // Update the attempt number so we don't re-enter this conditional
          signer.attempt.insert(id, attempt);

          let id = SignId { key: signer.keys.group_key().to_bytes().to_vec(), id, attempt };
          // Only preprocess if we're a signer
          if !id.signing_set(&signer.keys.params()).contains(&signer.keys.params().i()) {
            continue;
          }
          info!("selected to sign {} #{}", hex::encode(id.id), id.attempt);

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
          if signer.db.has_attempt(&id) {
            warn!(
              "already attempted {} #{}. this is an error if we didn't reboot",
              hex::encode(id.id),
              id.attempt
            );
            continue;
          }

          let mut txn = signer.db.0.txn();
          SubstrateSignerDb::<D>::attempt(&mut txn, &id);
          txn.commit();

          // b"substrate" is a literal from sp-core
          let machine = AlgorithmMachine::new(Schnorrkel::new(b"substrate"), signer.keys.clone());

          let (machine, preprocess) = machine.preprocess(&mut OsRng);
          signer.preprocessing.insert(id.id, machine);

          // Broadcast our preprocess
          if !signer.emit(SubstrateSignerEvent::ProcessorMessage(
            ProcessorMessage::BatchPreprocess { id, preprocess: preprocess.serialize() },
          )) {
            return;
          }
        }
      }
    }
  }
}

impl<D: Db> SubstrateSignerHandle<D> {
  pub async fn sign(&self, start: SystemTime, batch: Batch) {
    let mut signer = self.signer.write().await;
    if signer.db.completed(batch.block.0) {
      debug!("Sign batch order for ID we've already completed signing");
      // See BatchSigned for commentary on why this simply returns
      return;
    }
    signer.signable.insert(batch.block.0, (start, batch));
  }

  pub async fn handle(&self, msg: CoordinatorMessage) {
    self.signer.write().await.handle(msg).await;
  }
}
