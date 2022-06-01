use std::marker::Send;

use async_trait::async_trait;
use thiserror::Error;
use rand_core::{RngCore, CryptoRng};

use blake2::{digest::{Digest, Update}, Blake2b512};

use frost::{Curve, MultisigKeys};

mod coins;
mod wallet;

#[cfg(test)]
mod tests;

pub trait Output: Sized {
  type Id;

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

  fn id() -> &'static [u8];
  fn confirmations() -> usize;
  fn max_inputs() -> usize;
  fn max_outputs() -> usize;

  async fn get_height(&self) -> Result<usize, CoinError>;
  async fn get_block(&self, height: usize) -> Result<Self::Block, CoinError>;
  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: <Self::Curve as Curve>::G
  ) -> Vec<Self::Output>;

  async fn prepare_send<R: RngCore + CryptoRng>(
    &self,
    keys: MultisigKeys<Self::Curve>,
    label: Vec<u8>,
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

// Generate a view key for a given chain in a globally consistent manner regardless of the current
// group key
// Takes an index, k, for more modern privacy protocols which use multiple view keys
// Doesn't run Curve::hash_to_F, instead returning the hash object, due to hash_to_F being a FROST
// definition instead of a wide reduction from a hash object
pub fn view_key<C: Coin>(k: u64) -> Blake2b512 {
  Blake2b512::new().chain(b"Serai DEX View Key").chain(C::id()).chain(k.to_le_bytes())
}
