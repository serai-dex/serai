use std::{marker::Send, sync::Arc};

use async_trait::async_trait;
use thiserror::Error;

use transcript::RecommendedTranscript;
use frost::{curve::Curve, FrostKeys, sign::PreprocessMachine};

pub mod ethereum;
pub mod monero;
pub use self::monero::Monero;

#[derive(Clone, Error, Debug)]
pub enum CoinError {
  #[error("failed to connect to coin daemon")]
  ConnectionError
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
    keys: Arc<FrostKeys<Self::Curve>>,
    transcript: RecommendedTranscript,
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
  async fn mine_block(&self);

  #[cfg(test)]
  async fn test_send(&self, key: Self::Address);
}
