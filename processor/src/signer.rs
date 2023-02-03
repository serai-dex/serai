use std::collections::HashMap;

use tokio::sync::mpsc;

use frost::{
  ThresholdParams,
  sign::{PreprocessMachine, SignMachine},
};

use messages::sign::*;
use crate::{Db, coin::Coin};

const CHANNEL_EXPECT: &str = "Signer handler was dropped. Shutting down?";

#[derive(Debug)]
pub enum SignerOrder<C: Coin> {
  SignTransaction { id: [u8; 32], tx: C::SignableTransaction },
  CoordinatorMessage(CoordinatorMessage),
}

#[derive(Debug)]
pub enum SignerEvent<C: Coin> {
  SignedTransaction { id: [u8; 32], tx: C::Transaction },
  ProcessorMessage(ProcessorMessage),
}

pub type SignerOrderChannel<C> = mpsc::UnboundedSender<SignerOrder<C>>;
pub type SignerEventChannel<C> = mpsc::UnboundedReceiver<SignerEvent<C>>;

#[derive(Debug)]
struct SignerDb<D: Db>(D);
impl<D: Db> SignerDb<D> {
  fn sign_key(dst: &'static [u8], key: &[u8]) -> Vec<u8> {
    [b"SIGN", dst, key].concat().to_vec()
  }

  fn preprocess_key(id: &SignId) -> Vec<u8> {
    Self::sign_key(b"preprocess", &bincode::serialize(id).unwrap())
  }
  fn save_preprocess(&mut self, id: &SignId, preprocess: &HashMap<u16, Vec<u8>>) {
    self.0.put(&Self::preprocess_key(id), &bincode::serialize(preprocess).unwrap());
  }

  // Generic to the machine as this should eventually have both a Schnorr machine and a
  // PreprocessMachine
  fn preprocess<M: PreprocessMachine>(
    &self,
    id: &SignId,
    machine: &M::SignMachine,
  ) -> HashMap<u16, M::Preprocess> {
    bincode::deserialize::<HashMap<u16, Vec<u8>>>(&self.0.get(&Self::preprocess_key(id)).unwrap())
      .unwrap()
      .drain()
      .map(|(i, bytes)| (i, machine.read_preprocess::<&[u8]>(&mut bytes.as_ref()).unwrap()))
      .collect()
  }
}

#[derive(Debug)]
pub struct Signer<C: Coin, D: Db> {
  db: SignerDb<D>,

  orders: mpsc::UnboundedReceiver<SignerOrder<C>>,
  events: mpsc::UnboundedSender<SignerEvent<C>>,
}

#[derive(Debug)]
pub struct SignerHandle<C: Coin> {
  pub orders: SignerOrderChannel<C>,
  pub events: SignerEventChannel<C>,
}

// Coded so if the processor spontaneously reboot, one of two paths occur:
// 1) It either didn't send its response, so the attempt will be aborted
// 2) It did send its response, and has locally saved enough data to continue
impl<C: Coin, D: Db> Signer<C, D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(db: D) -> SignerHandle<C> {
    let (orders_send, orders_recv) = mpsc::unbounded_channel();
    let (events_send, events_recv) = mpsc::unbounded_channel();
    tokio::spawn(Signer { db: SignerDb(db), orders: orders_recv, events: events_send }.run());
    SignerHandle { orders: orders_send, events: events_recv }
  }

  // An async function, to be spawned on a task, to handle signing
  async fn run(mut self) {
    // Handle any new messages
    loop {
      // TODO: If we don't receive preprocesses/shares in time, create a new attempt
      match self.orders.recv().await.expect(CHANNEL_EXPECT) {
        SignerOrder::SignTransaction { id, tx } => todo!(),
        SignerOrder::CoordinatorMessage(CoordinatorMessage::SignPreprocesses {
          id,
          preprocesses,
        }) => todo!(),
        SignerOrder::CoordinatorMessage(CoordinatorMessage::SignShares { id, shares }) => todo!(),
      }
    }
  }
}
