use std::{marker::Send, collections::HashMap};

use async_trait::async_trait;
use thiserror::Error;

use frost::{curve::Ciphersuite, FrostError};

mod coin;
use coin::{CoinError, Coin};

mod wallet;

mod serai;

#[cfg(test)]
mod tests;

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
    &[C::ID, &k.to_le_bytes()].concat(),
  )
}
