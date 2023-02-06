use core::fmt;
use std::{
  time::{SystemTime, Duration},
  collections::HashMap,
};

use rand_core::OsRng;

use frost::{
  ThresholdParams,
  sign::{Writable, PreprocessMachine, SignMachine, SignatureMachine},
};

use log::{info, warn, error};
use tokio::{time::timeout, sync::mpsc};

use messages::sign::*;
use crate::{
  Db,
  coin::{Transaction, Coin},
};

#[derive(Debug)]
pub enum SignerOrder<C: Coin> {
  SignTransaction { id: [u8; 32], start: SystemTime, tx: C::SignableTransaction },
  CoordinatorMessage(CoordinatorMessage),
}

#[derive(Debug)]
pub enum SignerEvent<C: Coin> {
  // TODO: If this TX had payments, publish them to Substrate
  // TODO: Have a way to tell all other nodes we completed this signing session
  // Maybe if a node doesn't know, they should ask if it's been done? That voids needing
  // to publish results on-chain
  SignedTransaction { id: [u8; 32], tx: <C::Transaction as Transaction>::Id },
  ProcessorMessage(ProcessorMessage),
}

pub type SignerOrderChannel<C> = mpsc::UnboundedSender<SignerOrder<C>>;
pub type SignerEventChannel<C> = mpsc::UnboundedReceiver<SignerEvent<C>>;

#[derive(Debug)]
struct SignerDb<D: Db>(D);
impl<D: Db> SignerDb<D> {
  fn sign_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    [b"SIGNER", dst, key.as_ref()].concat().to_vec()
  }

  fn attempt_key(id: &SignId) -> Vec<u8> {
    Self::sign_key(b"attempt", bincode::serialize(id).unwrap())
  }
  fn attempt(&mut self, id: &SignId) {
    self.0.put(Self::attempt_key(id), []);
  }
  fn has_attempt(&mut self, id: &SignId) -> bool {
    self.0.get(Self::attempt_key(id)).is_some()
  }
}

/// Coded so if the processor spontaneously reboots, one of two paths occur:
/// 1) It either didn't send its response, so the attempt will be aborted
/// 2) It did send its response, and has locally saved enough data to continue
pub struct Signer<C: Coin, D: Db> {
  coin: C,
  db: SignerDb<D>,

  params: ThresholdParams,

  signable: HashMap<[u8; 32], (SystemTime, C::SignableTransaction)>,
  attempt: HashMap<[u8; 32], u32>,
  preprocessing: HashMap<[u8; 32], <C::TransactionMachine as PreprocessMachine>::SignMachine>,
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
  pub fn new(db: D, coin: C, params: ThresholdParams) -> SignerHandle<C> {
    let (orders_send, orders_recv) = mpsc::unbounded_channel();
    let (events_send, events_recv) = mpsc::unbounded_channel();
    tokio::spawn(
      Signer {
        coin,
        db: SignerDb(db),

        params,

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
    if !id.signing_set(&self.params).contains(&self.params.i()) {
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

          let id = SignId { id, attempt };
          // Only preprocess if we're a signer
          if !id.signing_set(&self.params).contains(&self.params.i()) {
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
          self.db.attempt(&id);

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
          // This needs to be re-issued on boot
          // TOOD: Remove this TODO once this flow is implemented elsewhere
          SignerOrder::SignTransaction { id, start, tx } => {
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

            if let Err(e) = self.coin.publish_transaction(&tx).await {
              error!("couldn't publish {:?}: {:?}", tx, e);
            } else {
              info!("published {:?}", tx.id());
            }

            if handle_send(
              self.events.send(SignerEvent::SignedTransaction { id: id.id, tx: tx.id() }),
            )
            .is_err()
            {
              return;
            }
          }
        },
      }
    }
  }
}
