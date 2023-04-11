use core::{marker::PhantomData, fmt};
use std::{
  sync::Arc,
  time::{SystemTime, Duration},
  collections::HashMap,
};

use rand_core::OsRng;

use group::GroupEncoding;
use frost::{
  ThresholdKeys,
  sign::{Writable, PreprocessMachine, SignMachine, SignatureMachine},
};

use log::{info, debug, warn, error};
use tokio::{
  sync::{RwLock, mpsc},
  time::sleep,
};

use messages::sign::*;
use crate::{
  DbTxn, Db,
  coins::{Transaction, Eventuality, Coin},
};

const CHANNEL_MSG: &str = "Signer handler was dropped. Shutting down?";

#[derive(Debug)]
pub enum SignerEvent<C: Coin> {
  SignedTransaction { id: [u8; 32], tx: <C::Transaction as Transaction<C>>::Id },
  ProcessorMessage(ProcessorMessage),
}

pub type SignerEventChannel<C> = mpsc::UnboundedReceiver<SignerEvent<C>>;

#[derive(Debug)]
struct SignerDb<C: Coin, D: Db>(D, PhantomData<C>);
impl<C: Coin, D: Db> SignerDb<C, D> {
  fn sign_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"SIGNER", dst, key)
  }

  fn completed_key(id: [u8; 32]) -> Vec<u8> {
    Self::sign_key(b"completed", id)
  }
  fn complete(
    &mut self,
    txn: &mut D::Transaction,
    id: [u8; 32],
    tx: &<C::Transaction as Transaction<C>>::Id,
  ) {
    // Transactions can be completed by multiple signatures
    // Save every solution in order to be robust
    let mut existing = txn.get(Self::completed_key(id)).unwrap_or(vec![]);

    // Don't add this TX if it's already present
    let tx_len = tx.as_ref().len();
    assert_eq!(existing.len() % tx_len, 0);

    let mut i = 0;
    while i < existing.len() {
      if existing[i .. (i + tx_len)].as_ref() == tx.as_ref() {
        return;
      }
      i += tx_len;
    }

    existing.extend(tx.as_ref());
    txn.put(Self::completed_key(id), existing);
  }
  fn completed(&self, id: [u8; 32]) -> Option<Vec<u8>> {
    self.0.get(Self::completed_key(id))
  }

  fn eventuality_key(id: [u8; 32]) -> Vec<u8> {
    Self::sign_key(b"eventuality", id)
  }
  fn save_eventuality(
    &mut self,
    txn: &mut D::Transaction,
    id: [u8; 32],
    eventuality: C::Eventuality,
  ) {
    txn.put(Self::eventuality_key(id), eventuality.serialize());
  }
  fn eventuality(&self, id: [u8; 32]) -> Option<C::Eventuality> {
    Some(
      C::Eventuality::read::<&[u8]>(&mut self.0.get(Self::eventuality_key(id))?.as_ref()).unwrap(),
    )
  }

  fn attempt_key(id: &SignId) -> Vec<u8> {
    Self::sign_key(b"attempt", bincode::serialize(id).unwrap())
  }
  fn attempt(&mut self, txn: &mut D::Transaction, id: &SignId) {
    txn.put(Self::attempt_key(id), []);
  }
  fn has_attempt(&mut self, id: &SignId) -> bool {
    self.0.get(Self::attempt_key(id)).is_some()
  }

  fn save_transaction(&mut self, txn: &mut D::Transaction, tx: &C::Transaction) {
    txn.put(Self::sign_key(b"tx", tx.id()), tx.serialize());
  }
}

pub struct Signer<C: Coin, D: Db> {
  coin: C,
  db: SignerDb<C, D>,

  keys: ThresholdKeys<C::Curve>,

  signable: HashMap<[u8; 32], (SystemTime, C::SignableTransaction)>,
  attempt: HashMap<[u8; 32], u32>,
  preprocessing: HashMap<[u8; 32], <C::TransactionMachine as PreprocessMachine>::SignMachine>,
  #[allow(clippy::type_complexity)]
  signing: HashMap<
    [u8; 32],
    <
      <C::TransactionMachine as PreprocessMachine>::SignMachine as SignMachine<C::Transaction>
    >::SignatureMachine,
  >,

  events: mpsc::UnboundedSender<SignerEvent<C>>,
}

impl<C: Coin, D: Db> fmt::Debug for Signer<C, D> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt
      .debug_struct("Signer")
      .field("coin", &self.coin)
      .field("signable", &self.signable)
      .field("attempt", &self.attempt)
      .finish_non_exhaustive()
  }
}

#[derive(Debug)]
pub struct SignerHandle<C: Coin, D: Db> {
  signer: Arc<RwLock<Signer<C, D>>>,
  pub events: SignerEventChannel<C>,
}

impl<C: Coin, D: Db> Signer<C, D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(db: D, coin: C, keys: ThresholdKeys<C::Curve>) -> SignerHandle<C, D> {
    let (events_send, events_recv) = mpsc::unbounded_channel();

    let signer = Arc::new(RwLock::new(Signer {
      coin,
      db: SignerDb(db, PhantomData),

      keys,

      signable: HashMap::new(),
      attempt: HashMap::new(),
      preprocessing: HashMap::new(),
      signing: HashMap::new(),

      events: events_send,
    }));

    tokio::spawn(Signer::run(signer.clone()));

    SignerHandle { signer, events: events_recv }
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
        warn!(
          "not attempting {} #{}. this is an error if we didn't reboot",
          hex::encode(id.id),
          id.attempt
        );
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

  fn emit(&mut self, event: SignerEvent<C>) -> bool {
    if self.events.send(event).is_err() {
      info!("{}", CHANNEL_MSG);
      false
    } else {
      true
    }
  }

  async fn eventuality_completion(
    &mut self,
    id: [u8; 32],
    tx_id: &<C::Transaction as Transaction<C>>::Id,
  ) {
    if let Some(eventuality) = self.db.eventuality(id) {
      // Transaction hasn't hit our mempool/was dropped for a different signature
      // The latter can happen given certain latency conditions/a single malicious signer
      // In the case of a single malicious signer, they can drag multiple honest
      // validators down with them, so we unfortunately can't slash on this case
      let Ok(tx) = self.coin.get_transaction(tx_id).await else {
        warn!(
          "a validator claimed {} completed {} yet we didn't have that TX in our mempool",
          hex::encode(tx_id),
          hex::encode(id),
        );
        return;
      };

      if self.coin.confirm_completion(&eventuality, &tx) {
        debug!("eventuality for {} resolved in TX {}", hex::encode(id), hex::encode(tx_id));

        // Stop trying to sign for this TX
        let mut txn = self.db.0.txn();
        self.db.save_transaction(&mut txn, &tx);
        self.db.complete(&mut txn, id, tx_id);
        txn.commit();

        self.signable.remove(&id);
        self.attempt.remove(&id);
        self.preprocessing.remove(&id);
        self.signing.remove(&id);

        self.emit(SignerEvent::SignedTransaction { id, tx: tx.id() });
      } else {
        warn!(
          "a validator claimed {} completed {} when it did not",
          hex::encode(tx_id),
          hex::encode(id)
        );
      }
    } else {
      debug!(
        "signer {} informed of the completion of {}. {}",
        hex::encode(self.keys.group_key().to_bytes()),
        hex::encode(id),
        "this signer did not have/has already completed that plan",
      );
    }
  }

  async fn handle(&mut self, msg: CoordinatorMessage) {
    match msg {
      CoordinatorMessage::Preprocesses { id, mut preprocesses } => {
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

        // Use an empty message, as expected of TransactionMachines
        let (machine, share) = match machine.sign(preprocesses, &[]) {
          Ok(res) => res,
          Err(e) => todo!("malicious signer: {:?}", e),
        };
        self.signing.insert(id.id, machine);

        // Broadcast our share
        self.emit(SignerEvent::ProcessorMessage(ProcessorMessage::Share {
          id,
          share: share.serialize(),
        }));
      }

      CoordinatorMessage::Shares { id, mut shares } => {
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

        let tx = match machine.complete(shares) {
          Ok(res) => res,
          Err(e) => todo!("malicious signer: {:?}", e),
        };

        // Save the transaction in case it's needed for recovery
        let mut txn = self.db.0.txn();
        self.db.save_transaction(&mut txn, &tx);
        let tx_id = tx.id();
        self.db.complete(&mut txn, id.id, &tx_id);
        txn.commit();

        // Publish it
        if let Err(e) = self.coin.publish_transaction(&tx).await {
          error!("couldn't publish {:?}: {:?}", tx, e);
        } else {
          info!("published {}", hex::encode(&tx_id));
        }

        // Stop trying to sign for this TX
        assert!(self.signable.remove(&id.id).is_some());
        assert!(self.attempt.remove(&id.id).is_some());
        assert!(self.preprocessing.remove(&id.id).is_none());
        assert!(self.signing.remove(&id.id).is_none());

        self.emit(SignerEvent::SignedTransaction { id: id.id, tx: tx_id });
      }

      CoordinatorMessage::Completed { key: _, id, tx: mut tx_vec } => {
        let mut tx = <C::Transaction as Transaction<C>>::Id::default();
        if tx.as_ref().len() != tx_vec.len() {
          tx_vec.truncate(2 * tx.as_ref().len());
          warn!(
            "a validator claimed {} completed {} yet that's not a valid TX ID",
            hex::encode(&tx),
            hex::encode(id),
          );
          return;
        }
        tx.as_mut().copy_from_slice(&tx_vec);

        self.eventuality_completion(id, &tx).await;
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
          let (start, tx) = &signer.signable[&id];
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

          // Start this attempt
          // Clone the TX so we don't have an immutable borrow preventing the below mutable actions
          // (also because we do need an owned tx anyways)
          let tx = tx.clone();

          // Delete any existing machines
          signer.preprocessing.remove(&id);
          signer.signing.remove(&id);

          // Update the attempt number so we don't re-enter this conditional
          signer.attempt.insert(id, attempt);

          let id =
            SignId { key: signer.keys.group_key().to_bytes().as_ref().to_vec(), id, attempt };
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
          signer.db.attempt(&mut txn, &id);
          txn.commit();

          // Attempt to create the TX
          let machine = match signer.coin.attempt_send(tx).await {
            Err(e) => {
              error!("failed to attempt {}, #{}: {:?}", hex::encode(id.id), id.attempt, e);
              continue;
            }
            Ok(machine) => machine,
          };

          let (machine, preprocess) = machine.preprocess(&mut OsRng);
          signer.preprocessing.insert(id.id, machine);

          // Broadcast our preprocess
          if !signer.emit(SignerEvent::ProcessorMessage(ProcessorMessage::Preprocess {
            id,
            preprocess: preprocess.serialize(),
          })) {
            return;
          }
        }
      }
    }
  }
}

impl<C: Coin, D: Db> SignerHandle<C, D> {
  pub async fn keys(&self) -> ThresholdKeys<C::Curve> {
    self.signer.read().await.keys.clone()
  }

  pub async fn sign_transaction(
    &self,
    id: [u8; 32],
    start: SystemTime,
    tx: C::SignableTransaction,
    eventuality: C::Eventuality,
  ) {
    let mut signer = self.signer.write().await;

    if let Some(txs) = signer.db.completed(id) {
      debug!("SignTransaction order for ID we've already completed signing");

      // Find the first instance we noted as having completed *and can still get from our node*
      let mut tx = None;
      let mut buf = <C::Transaction as Transaction<C>>::Id::default();
      let tx_id_len = buf.as_ref().len();
      assert_eq!(txs.len() % tx_id_len, 0);
      for id in 0 .. (txs.len() / tx_id_len) {
        let start = id * tx_id_len;
        buf.as_mut().copy_from_slice(&txs[start .. (start + tx_id_len)]);
        if signer.coin.get_transaction(&buf).await.is_ok() {
          tx = Some(buf);
          break;
        }
      }

      // Fire the SignedTransaction event again
      if let Some(tx) = tx {
        if !signer.emit(SignerEvent::SignedTransaction { id, tx }) {
          return;
        }
      } else {
        warn!("completed signing {} yet couldn't get any of the completing TXs", hex::encode(id));
      }
      return;
    }

    let mut txn = signer.db.0.txn();
    signer.db.save_eventuality(&mut txn, id, eventuality);
    txn.commit();

    signer.signable.insert(id, (start, tx));
  }

  pub async fn eventuality_completion(
    &self,
    id: [u8; 32],
    tx: &<C::Transaction as Transaction<C>>::Id,
  ) {
    self.signer.write().await.eventuality_completion(id, tx).await;
  }

  pub async fn handle(&self, msg: CoordinatorMessage) {
    self.signer.write().await.handle(msg).await;
  }
}
