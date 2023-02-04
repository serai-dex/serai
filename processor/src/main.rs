use std::{marker::Send, collections::HashMap};

use async_trait::async_trait;
use thiserror::Error;

use frost::{curve::Ciphersuite, ThresholdParams, FrostError};

use messages::{ProcessorMessage, CoordinatorMessage};

mod coin;
use coin::{CoinError, Coin};

mod key_gen;
use key_gen::KeyGen;
mod signer;
use signer::{Signer, SignerOrder, SignerEvent};

mod scanner;
use scanner::Scanner;
mod scheduler;
use scheduler::Scheduler;

mod wallet;

#[cfg(test)]
mod tests;

pub trait Db: 'static + Send + Sync {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>);
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>>;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Payment<C: Coin> {
  address: C::Address,
  amount: u64,
}

#[derive(Clone, Debug)]
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

// TODO: Grab RocksDB
#[derive(Clone, Debug)]
struct MemDb(HashMap<Vec<u8>, Vec<u8>>);
impl MemDb {
  pub(crate) fn new() -> MemDb {
    MemDb(HashMap::new())
  }
}
impl Default for MemDb {
  fn default() -> MemDb {
    MemDb::new()
  }
}

impl Db for MemDb {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    self.0.insert(key.as_ref().to_vec(), value.as_ref().to_vec());
  }
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    self.0.get(key.as_ref()).cloned()
  }
}

#[tokio::main]
async fn main() {
  use crate::coin::Monero;
  let coin = Monero::new("".to_string()).await;
  let db = MemDb::new();

  let mut key_gen = KeyGen::<<Monero as Coin>::Curve, _>::new(db.clone());
  let mut signer = Signer::new(db.clone(), coin.clone(), ThresholdParams::new(0, 0, 0).unwrap());

  let scanner = Scanner::new(coin, db);
  let scheduler = Scheduler::<Monero>::new(<Monero as Coin>::Curve::generator());

  let (to_coordinator, _fake_coordinator_recv) =
    tokio::sync::mpsc::unbounded_channel::<ProcessorMessage>();
  let (_fake_coordinator_send, mut from_coordinator) =
    tokio::sync::mpsc::unbounded_channel::<CoordinatorMessage>();

  loop {
    tokio::select! {
      msg = from_coordinator.recv() => {
        match msg.expect("Coordinator channel was dropped. Shutting down?") {
          CoordinatorMessage::KeyGen(msg) => key_gen.coordinator.send(msg).unwrap(),
          CoordinatorMessage::Sign(msg) => {
            signer.orders.send(SignerOrder::CoordinatorMessage(msg)).unwrap()
          }
        }
      },

      msg = key_gen.processor.recv() => {
        to_coordinator.send(ProcessorMessage::KeyGen(msg.unwrap())).unwrap();
      },

      msg = signer.events.recv() => {
        match msg.unwrap() {
          SignerEvent::SignedTransaction { id: _, tx: _ } => todo!(),
          SignerEvent::ProcessorMessage(msg) => {
            to_coordinator.send(ProcessorMessage::Sign(msg)).unwrap();
          },
        }
      },
    }
  }
}
