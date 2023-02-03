use std::{marker::Send, collections::HashMap};

use async_trait::async_trait;
use thiserror::Error;

use frost::{curve::Ciphersuite, FrostError};

mod coin;
use coin::{CoinError, Coin};

mod key_gen;
use key_gen::KeyGen;
mod signer;
use signer::Signer;

mod scanner;
use scanner::Scanner;
mod scheduler;
use scheduler::Scheduler;

mod wallet;

#[cfg(test)]
mod tests;

pub trait Db: 'static + Send + Sync {
  fn put(&mut self, key: &[u8], value: &[u8]);
  fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Payment<C: Coin> {
  address: C::Address,
  amount: u64,
}

#[derive(Clone, Debug)]
pub struct Transaction<C: Coin> {
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
  fn put(&mut self, key: &[u8], value: &[u8]) {
    self.0.insert(key.to_vec(), value.to_vec());
  }
  fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
    self.0.get(key).cloned()
  }
}

#[tokio::main]
async fn main() {
  use crate::coin::Monero;
  let coin = Monero::new("".to_string()).await;
  let db = MemDb::new();

  let _key_gen = KeyGen::<<Monero as Coin>::Curve, _>::new(db.clone());
  let _signer = Signer::new(coin.clone(), db.clone());

  let _scanner = Scanner::new(coin, db);
  let _scheduler = Scheduler::<Monero>::new(<Monero as Coin>::Curve::generator());
}
