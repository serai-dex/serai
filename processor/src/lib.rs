use std::{marker::Send, io::Cursor, collections::HashMap};

use async_trait::async_trait;
use thiserror::Error;

use frost::FrostError;

pub use serai_coin as coin;
use coin::CoinError;

mod wallet;

#[cfg(test)]
mod tests;

#[derive(Clone, Error, Debug)]
pub enum NetworkError {}

#[async_trait]
pub trait Network: Send {
  async fn round(&mut self, data: Vec<u8>) -> Result<HashMap<u16, Cursor<Vec<u8>>>, NetworkError>;
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
