use std::marker::Send;

use async_trait::async_trait;
use thiserror::Error;

use transcript::RecommendedTranscript;
use frost::{
  curve::{Ciphersuite, Curve},
  ThresholdKeys,
  sign::PreprocessMachine,
};

pub mod monero;
pub use self::monero::Monero;

#[derive(Clone, Copy, Error, Debug)]
pub enum CoinError {
  #[error("failed to connect to coin daemon")]
  ConnectionError,
}

pub trait Block: Sized + Clone {
  type Id: Clone + Copy + AsRef<[u8]>;
  fn id(&self) -> Self::Id;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OutputType {
  External,
  Branch,
  Change,
}

pub trait Output: Sized + Clone {
  type Id: Clone + Copy + AsRef<[u8]>;

  fn kind(&self) -> OutputType;

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
  type Block: Block;

  type Output: Output;
  type SignableTransaction;
  type TransactionMachine: PreprocessMachine<Signature = Self::Transaction>;

  type Address: Send;

  const ID: &'static [u8];
  const CONFIRMATIONS: usize;
  const MAX_INPUTS: usize;
  const MAX_OUTPUTS: usize; // TODO: Decide if this includes change or not

  /// Address for the given group key to receive external coins to.
  // Doesn't have to take self, enables some level of caching which is pleasant
  fn address(&self, key: <Self::Curve as Ciphersuite>::G) -> Self::Address;
  /// Address for the given group key to use for scheduled branches.
  fn branch_address(&self, key: <Self::Curve as Ciphersuite>::G) -> Self::Address;

  async fn get_latest_block_number(&self) -> Result<usize, CoinError>;
  async fn get_block(&self, number: usize) -> Result<Self::Block, CoinError>;
  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: <Self::Curve as Ciphersuite>::G,
  ) -> Result<Vec<Self::Output>, CoinError>;

  #[allow(clippy::too_many_arguments)]
  async fn prepare_send(
    &self,
    keys: ThresholdKeys<Self::Curve>,
    transcript: RecommendedTranscript,
    block_number: usize,
    inputs: Vec<Self::Output>,
    payments: &[(Self::Address, u64)],
    change: Option<<Self::Curve as Ciphersuite>::G>,
    fee: Self::Fee,
  ) -> Result<Self::SignableTransaction, CoinError>;

  async fn attempt_send(
    &self,
    transaction: Self::SignableTransaction,
  ) -> Result<Self::TransactionMachine, CoinError>;

  async fn publish_transaction(
    &self,
    tx: &Self::Transaction,
  ) -> Result<(Vec<u8>, Vec<<Self::Output as Output>::Id>), CoinError>;

  #[cfg(test)]
  async fn get_fee(&self) -> Self::Fee;

  #[cfg(test)]
  async fn mine_block(&self);

  #[cfg(test)]
  async fn test_send(&self, key: Self::Address);
}
