use core::{marker::PhantomData, fmt};
use std::{
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
use tokio::{time::timeout, sync::mpsc};

use messages::sign::*;
use crate::{
  DbTxn, Db,
  coins::{Transaction, Eventuality, Coin},
};

#[derive(Debug)]
pub enum SignerOrder<C: Coin> {
  SignTransaction {
    id: [u8; 32],
    start: SystemTime,
    tx: C::SignableTransaction,
    eventuality: C::Eventuality,
  },
  CoordinatorMessage(CoordinatorMessage),
}

#[derive(Debug)]
pub enum SignerEvent<C: Coin> {
  SignedTransaction { id: [u8; 32], tx: <C::Transaction as Transaction<C>>::Id },
  ProcessorMessage(ProcessorMessage),
}

pub type SignerOrderChannel<C> = mpsc::UnboundedSender<SignerOrder<C>>;
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
    tx: <C::Transaction as Transaction<C>>::Id,
  ) {
    // Transactions can be completed by multiple signatures
    // Save every solution in order to be robust
    let mut existing = txn.get(Self::completed_key(id)).unwrap_or(vec![]);
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

  fn save_transaction(&mut self, txn: &mut D::Transaction, id: [u8; 32], tx: Vec<u8>) {
    txn.put(Self::sign_key(b"tx", id), tx);
  }
}

/// Coded so if the processor spontaneously reboots, one of two paths occur:
/// 1) It either didn't send its response, so the attempt will be aborted
/// 2) It did send its response, and has locally saved enough data to continue
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

  orders: mpsc::UnboundedReceiver<SignerOrder<C>>,
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
pub struct SignerHandle<C: Coin> {
  pub orders: SignerOrderChannel<C>,
  pub events: SignerEventChannel<C>,
}

impl<C: Coin, D: Db> Signer<C, D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(db: D, coin: C, keys: ThresholdKeys<C::Curve>) -> SignerHandle<C> {
    let (orders_send, orders_recv) = mpsc::unbounded_channel();
    let (events_send, events_recv) = mpsc::unbounded_channel();
    tokio::spawn(
      Signer {
        coin,
        db: SignerDb(db, PhantomData),

        keys,

        signable: HashMap::new(),
        attempt: HashMap::new(),
        preprocessing: HashMap::new(),
        signing: HashMap::new(),

        orders: orders_recv,
        events: events_send,
      }
      .run(),
    );
    SignerHandle { orders: orders_send, events: events_recv }
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
        warn!("not attempting {:?}. this is an error if we didn't reboot", id);
        // Don't panic on the assumption we rebooted
        Err(())?;
      }
      Some(attempt) => {
        // This could be an old attempt, or it may be a 'future' attempt if we rebooted and
        // our SystemTime wasn't monotonic, as it may be
        if attempt != &id.attempt {
          Err(())?;
        }
      }
    }

    Ok(())
  }

  // An async function, to be spawned on a task, to handle signing
  async fn run(mut self) {
    const CHANNEL_MSG: &str = "Signer handler was dropped. Shutting down?";
    let handle_recv = |channel: Option<SignerOrder<C>>| {
      if channel.is_none() {
        info!("{}", CHANNEL_MSG);
      }
      channel
    };
    let handle_send = |channel: Result<_, _>| {
      if channel.is_err() {
        info!("{}", CHANNEL_MSG);
      }
      channel
    };

    // Handle any new messages
    loop {
      // Check if we need to start any new attempts for any current TXs
      for (id, (start, tx)) in self.signable.iter() {
        const SIGN_TIMEOUT: u64 = 30;
        let attempt = u32::try_from(
          SystemTime::now().duration_since(*start).unwrap_or(Duration::ZERO).as_secs() /
            SIGN_TIMEOUT,
        )
        .unwrap();

        // If we haven't started this attempt, do so
        if (!self.attempt.contains_key(id)) || (self.attempt[id] < attempt) {
          // Delete any existing machines
          self.preprocessing.remove(id);
          self.signing.remove(id);

          // Update the attempt number so we don't re-enter this conditional
          let id = *id;
          self.attempt.insert(id, attempt);

          let id = SignId { key: self.keys.group_key().to_bytes().as_ref().to_vec(), id, attempt };
          // Only preprocess if we're a signer
          if !id.signing_set(&self.keys.params()).contains(&self.keys.params().i()) {
            continue;
          }
          info!("selected to sign {:?}", id);

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
          if self.db.has_attempt(&id) {
            warn!("already attempted {:?}. this is an error if we didn't reboot", id);
            continue;
          }

          let mut txn = self.db.0.txn();
          self.db.attempt(&mut txn, &id);
          txn.commit();

          // Attempt to create the TX
          let machine = match self.coin.attempt_send(tx.clone()).await {
            Err(e) => {
              error!("failed to attempt {:?}: {:?}", id, e);
              continue;
            }
            Ok(machine) => machine,
          };

          let (machine, preprocess) = machine.preprocess(&mut OsRng);
          self.preprocessing.insert(id.id, machine);

          // Broadcast our preprocess
          if handle_send(self.events.send(SignerEvent::ProcessorMessage(
            ProcessorMessage::Preprocess { id, preprocess: preprocess.serialize() },
          )))
          .is_err()
          {
            return;
          }
        }
      }

      match timeout(Duration::from_secs(1), self.orders.recv()).await {
        Err(_) => continue,
        Ok(order) => match {
          match handle_recv(order) {
            None => return,
            Some(order) => order,
          }
        } {
          SignerOrder::SignTransaction { id, start, tx, eventuality } => {
            if let Some(txs) = self.db.completed(id) {
              debug!("SignTransaction order for ID we've already completed signing");

              let mut tx = <C::Transaction as Transaction<C>>::Id::default();
              // Use the first instance we noted as having completed
              let tx_id_len = tx.as_ref().len();
              tx.as_mut().copy_from_slice(&txs[.. tx_id_len]);
              if handle_send(self.events.send(SignerEvent::SignedTransaction { id, tx })).is_err() {
                return;
              }
              continue;
            }

            let mut txn = self.db.0.txn();
            self.db.save_eventuality(&mut txn, id, eventuality);
            txn.commit();

            self.signable.insert(id, (start, tx));
          }

          SignerOrder::CoordinatorMessage(CoordinatorMessage::Preprocesses {
            id,
            mut preprocesses,
          }) => {
            if self.verify_id(&id).is_err() {
              continue;
            }

            let machine = match self.preprocessing.remove(&id.id) {
              // Either rebooted or RPC error, or some invariant
              None => {
                warn!("not preprocessing for {:?}. this is an error if we didn't reboot", id);
                continue;
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
            if handle_send(self.events.send(SignerEvent::ProcessorMessage(
              ProcessorMessage::Share { id, share: share.serialize() },
            )))
            .is_err()
            {
              return;
            }
          }

          SignerOrder::CoordinatorMessage(CoordinatorMessage::Shares { id, mut shares }) => {
            if self.verify_id(&id).is_err() {
              continue;
            }

            let machine = match self.signing.remove(&id.id) {
              // Rebooted, RPC error, or some invariant
              None => {
                // If preprocessing has this ID, it means we were never set the preprocess by the
                // coordinator
                if self.preprocessing.contains_key(&id.id) {
                  panic!("never preprocessed yet signing?");
                }

                warn!("not preprocessing for {:?}. this is an error if we didn't reboot", id);
                continue;
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
            self.db.save_transaction(&mut txn, id.id, tx.serialize());
            self.db.complete(&mut txn, id.id, tx.id());
            txn.commit();

            // Publish it
            if let Err(e) = self.coin.publish_transaction(&tx).await {
              error!("couldn't publish {:?}: {:?}", tx, e);
            } else {
              info!("published {:?}", hex::encode(tx.id()));
            }

            // Stop trying to sign for this TX
            assert!(self.signable.remove(&id.id).is_some());
            assert!(self.attempt.remove(&id.id).is_some());
            assert!(self.preprocessing.remove(&id.id).is_none());
            assert!(self.signing.remove(&id.id).is_none());

            if handle_send(
              self.events.send(SignerEvent::SignedTransaction { id: id.id, tx: tx.id() }),
            )
            .is_err()
            {
              return;
            }
          }

          SignerOrder::CoordinatorMessage(CoordinatorMessage::Completed { id, tx: tx_vec }) => {
            let mut tx = <C::Transaction as Transaction<C>>::Id::default();
            if tx.as_ref().len() != tx_vec.len() {
              warn!(
                "a validator claimed {} completed {id:?} yet that's not a valid TX ID",
                hex::encode(&tx)
              );
              continue;
            }
            tx.as_mut().copy_from_slice(&tx_vec);

            if let Some(eventuality) = self.db.eventuality(id.id) {
              match self.coin.confirm_completion(&eventuality, &tx).await {
                Ok(true) => {
                  // Stop trying to sign for this TX
                  let mut txn = self.db.0.txn();
                  self.db.complete(&mut txn, id.id, tx.clone());
                  txn.commit();
                  self.signable.remove(&id.id);
                  self.attempt.remove(&id.id);
                  self.preprocessing.remove(&id.id);
                  self.signing.remove(&id.id);

                  if handle_send(self.events.send(SignerEvent::SignedTransaction { id: id.id, tx }))
                    .is_err()
                  {
                    return;
                  }
                }

                Ok(false) => {
                  warn!(
                    "a validator claimed {} completed {id:?} when it did not",
                    hex::encode(&tx)
                  );
                }

                // Transaction hasn't hit our mempool/was dropped for a different signature
                // The latter can happen given certain latency conditions/a single malicious signer
                // In the case of a signle malicious signer, they can drag multiple honest
                // validators down with them, so we unfortunately can't slash on this case
                Err(_) => todo!("queue checking eventualities"),
              }
            } else {
              todo!("queue checking eventualities")
            }
          }
        },
      }
    }
  }
}
