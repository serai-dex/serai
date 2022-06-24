use std::{marker::Send, sync::Arc, collections::HashMap};

use async_trait::async_trait;
use thiserror::Error;

use frost::{Curve, FrostError, MultisigKeys, sign::PreprocessMachine};

pub(crate) use monero_serai::frost::Transcript;

mod coins;
mod wallet;

#[cfg(test)]
mod tests;

#[derive(Clone, Error, Debug)]
pub enum CoinError {
  #[error("failed to connect to coin daemon")]
  ConnectionError
}

#[derive(Clone, Error, Debug)]
pub enum NetworkError {}

#[derive(Clone, Error, Debug)]
pub enum SignError {
  #[error("coin had an error {0}")]
  CoinError(CoinError),
  #[error("network had an error {0}")]
  NetworkError(NetworkError),
  #[error("FROST had an error {0}")]
  FrostError(FrostError)
}

#[async_trait]
pub trait Network: Send {
  async fn round(&mut self, data: Vec<u8>) -> Result<HashMap<u16, Vec<u8>>, NetworkError>;
}

pub trait Output: Sized + Clone {
  type Id: AsRef<[u8]>;

  fn id(&self) -> Self::Id;
  fn amount(&self) -> u64;

  fn serialize(&self) -> Vec<u8>;
  fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self>;
}

#[async_trait]
pub trait Coin {
  type Curve: Curve;

  type Fee: Copy;
  type Transaction;
  type Block;

  type Output: Output;
  type SignableTransaction;
  type TransactionMachine: PreprocessMachine<Signature = Self::Transaction>;

  type Address: Send;

  const ID: &'static [u8];
  const CONFIRMATIONS: usize;
  const MAX_INPUTS: usize;
  const MAX_OUTPUTS: usize; // TODO: Decide if this includes change or not

  // Doesn't have to take self, enables some level of caching which is pleasant
  fn address(&self, key: <Self::Curve as Curve>::G) -> Self::Address;

  async fn get_height(&self) -> Result<usize, CoinError>;
  async fn get_block(&self, height: usize) -> Result<Self::Block, CoinError>;
  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: <Self::Curve as Curve>::G
  ) -> Vec<Self::Output>;

  async fn prepare_send(
    &self,
    keys: Arc<MultisigKeys<Self::Curve>>,
    transcript: Transcript,
    height: usize,
    inputs: Vec<Self::Output>,
    payments: &[(Self::Address, u64)],
    fee: Self::Fee
  ) -> Result<Self::SignableTransaction, CoinError>;

  async fn attempt_send(
    &self,
    transaction: Self::SignableTransaction,
    included: &[u16]
  ) -> Result<Self::TransactionMachine, CoinError>;

  async fn publish_transaction(
    &self,
    tx: &Self::Transaction
  ) -> Result<(Vec<u8>, Vec<<Self::Output as Output>::Id>), CoinError>;

  #[cfg(test)]
  async fn mine_block(&self, address: Self::Address);

  #[cfg(test)]
  async fn test_send(&self, key: Self::Address);
}

// Generate a static view key for a given chain in a globally consistent manner
// Doesn't consider the current group key to increase the simplicity of verifying Serai's status
// Takes an index, k, for more modern privacy protocols which use multiple view keys
pub fn view_key<C: Coin>(k: u64) -> <C::Curve as Curve>::F {
  C::Curve::hash_to_F(b"Serai DEX View Key", &[C::ID, &k.to_le_bytes()].concat())
}
