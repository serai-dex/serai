use core::fmt::Debug;
use std::{
  sync::{Arc, RwLock},
  collections::HashMap,
};

use async_trait::async_trait;
use thiserror::Error;

use group::GroupEncoding;
use frost::{curve::Ciphersuite, FrostError};

use messages::{CoordinatorMessage, ProcessorMessage, substrate};

mod coin;
use coin::{CoinError, Block, Coin};

mod key_gen;
use key_gen::{KeyGenOrder, KeyGenEvent, KeyGen};

mod signer;
use signer::{SignerOrder, SignerEvent, Signer};

mod scanner;
use scanner::{ScannerOrder, ScannerEvent, Scanner};

mod scheduler;
use scheduler::Scheduler;

#[cfg(test)]
mod tests;

pub trait Db: 'static + Send + Sync + Clone + Debug {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>);
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>>;
  fn del(&mut self, key: impl AsRef<[u8]>);
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Payment<C: Coin> {
  address: C::Address,
  amount: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Plan<C: Coin> {
  pub inputs: Vec<C::Output>,
  pub payments: Vec<Payment<C>>,
  pub change: bool,
}

#[derive(Clone, Error, Debug)]
pub enum NetworkError {}

#[async_trait]
pub trait Network: Send {
  async fn round(&mut self, data: Vec<u8>) -> Result<HashMap<u16, Vec<u8>>, NetworkError>;
}

#[derive(Clone, Error, Debug)]
pub enum SignError {
  #[error("FROST had an error {0}")]
  FrostError(FrostError),
  #[error("coin had an error {0}")]
  CoinError(CoinError),
  #[error("network had an error {0}")]
  NetworkError(NetworkError),
}

// Generate a static additional key for a given chain in a globally consistent manner
// Doesn't consider the current group key to increase the simplicity of verifying Serai's status
// Takes an index, k, to support protocols which use multiple secondary keys
// Presumably a view key
pub(crate) fn additional_key<C: Coin>(k: u64) -> <C::Curve as Ciphersuite>::F {
  <C::Curve as Ciphersuite>::hash_to_F(
    b"Serai DEX Additional Key",
    &[C::ID.as_bytes(), &k.to_le_bytes()].concat(),
  )
}

// TODO: Replace this with RocksDB
#[derive(Clone, Debug)]
struct MemDb(Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>);
impl MemDb {
  pub(crate) fn new() -> MemDb {
    MemDb(Arc::new(RwLock::new(HashMap::new())))
  }
}
impl Default for MemDb {
  fn default() -> MemDb {
    MemDb::new()
  }
}

impl Db for MemDb {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    self.0.write().unwrap().insert(key.as_ref().to_vec(), value.as_ref().to_vec());
  }
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    self.0.read().unwrap().get(key.as_ref()).cloned()
  }
  fn del(&mut self, key: impl AsRef<[u8]>) {
    self.0.write().unwrap().remove(key.as_ref());
  }
}

async fn run<C: Coin, D: Db>(db: D, coin: C) {
  let mut key_gen = KeyGen::<C::Curve, _>::new(db.clone());
  let mut scanner = Scanner::new(coin.clone(), db.clone());

  let mut schedulers = HashMap::new();
  // TODO: load existing schedulers
  let mut signers = HashMap::new();
  // TODO: Load existing signers

  let mut track_key = |activation_number, key| {
    scanner.orders.send(ScannerOrder::RotateKey { activation_number, key }).unwrap();
    schedulers.insert(key.to_bytes().as_ref().to_vec(), Scheduler::<C>::new(key));
  };

  let (to_coordinator, _fake_coordinator_recv) =
    tokio::sync::mpsc::unbounded_channel::<ProcessorMessage>();
  let (_fake_coordinator_send, mut from_coordinator) =
    tokio::sync::mpsc::unbounded_channel::<CoordinatorMessage>();

  loop {
    tokio::select! {
      msg = from_coordinator.recv() => {
        match msg.expect("Coordinator channel was dropped. Shutting down?") {
          CoordinatorMessage::KeyGen(msg) => {
            key_gen.orders.send(KeyGenOrder::CoordinatorMessage(msg)).unwrap()
          },
          CoordinatorMessage::Sign(msg) => {
            todo!()
            // signer.orders.send(SignerOrder::CoordinatorMessage(msg)).unwrap()
          },
          CoordinatorMessage::Substrate(
            substrate::CoordinatorMessage::BlockAcknowledged { key, block }
          ) => {
            let mut block_id = <C::Block as Block>::Id::default();
            block_id.as_mut().copy_from_slice(&block);

            let scheduler =
              schedulers
                .get_mut(&key)
                .expect("key we don't have a scheduler for acknowledged a block");
            let plans = scheduler.add_outputs(scanner.outputs(&key, &block_id));
            todo!(); // Handle plans
          }
          CoordinatorMessage::Substrate(substrate::CoordinatorMessage::Burns(burns)) => {
            let scheduler = todo!(); // Use the latest key?
            // TODO: OutInstruction data
            /*
            let plans = scheduler.schedule(burns.drain(..).filter_map(|burn| Some(Payment {
              address: C::Address::try_from(burn.data.address.consume()).ok()?,
              amount: burn.amount,
            })));
            */
            todo!(); // Handle plans
          }
        }
      },

      msg = key_gen.events.recv() => {
        match msg.unwrap() {
          KeyGenEvent::KeyConfirmed { set, params, key } => {
            let activation_number = coin.get_latest_block_number().await.unwrap(); // TODO
            track_key(activation_number, key);
            signers.insert(
              key.to_bytes().as_ref().to_vec(),
              Signer::new(db.clone(), coin.clone(), params)
            );
          },
          KeyGenEvent::ProcessorMessage(msg) => {
            to_coordinator.send(ProcessorMessage::KeyGen(msg)).unwrap();
          },
        }
      },

      msg = scanner.events.recv() => {
        // These need to be sent to the coordinator which needs to check they aren't replayed
        // TODO
        match msg.unwrap() {
          ScannerEvent::Block(number, id) => todo!(),
          ScannerEvent::Outputs(key, block, outputs) => todo!(),
        }
      },

      /*
      msg = signer.events.recv() => {
        match msg.unwrap() {
          SignerEvent::SignedTransaction { id: _, tx: _ } => todo!(),
          SignerEvent::ProcessorMessage(msg) => {
            to_coordinator.send(ProcessorMessage::Sign(msg)).unwrap();
          },
        }
      },
      */
    }
  }
}

#[tokio::main]
async fn main() {
  use crate::coin::Monero;
  let coin = Monero::new("".to_string()).await;

  let db = MemDb::new();
  run(db, coin).await;
}
