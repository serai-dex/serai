use std::{marker::Send, sync::Arc};

use async_trait::async_trait;
use thiserror::Error;
use rand_core::{RngCore, CryptoRng};

use frost::{Curve, MultisigKeys};

pub(crate) use monero_serai::frost::Transcript;

mod coins;
mod wallet;

#[cfg(test)]
mod tests;

pub trait Output: Sized + Clone {
  type Id: AsRef<[u8]>;

  fn id(&self) -> Self::Id;
  fn amount(&self) -> u64;

  fn serialize(&self) -> Vec<u8>;
  fn deserialize<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self>;
}

#[derive(Clone, Error, Debug)]
pub enum CoinError {
  #[error("failed to connect to coin daemon")]
  ConnectionError
}

#[async_trait]
pub trait Coin {
  type Curve: Curve;

  type Output: Output;
  type Block;
  type SignableTransaction;

  type Address: Send;

  const ID: &'static [u8];
  const CONFIRMATIONS: usize;
  const MAX_INPUTS: usize;
  const MAX_OUTPUTS: usize;

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
    payments: &[(Self::Address, u64)]
  ) -> Result<Self::SignableTransaction, CoinError>;

  async fn attempt_send<R: RngCore + CryptoRng + Send>(
    &self,
    rng: &mut R,
    transaction: Self::SignableTransaction,
    included: &[u16]
  ) -> Result<(Vec<u8>, Vec<<Self::Output as Output>::Id>), CoinError>;
}

// Generate a static view key for a given chain in a globally consistent manner
// Doesn't consider the current group key to increase the simplicity of verifying Serai's status
// Takes an index, k, for more modern privacy protocols which use multiple view keys
pub fn view_key<C: Coin>(k: u64) -> <C::Curve as Curve>::F {
  C::Curve::hash_to_F(b"Serai DEX View Key", &[C::ID, &k.to_le_bytes()].concat())
}
