use std::{collections::HashMap, marker::Send};

use async_trait::async_trait;
use thiserror::Error;

use frost::{curve::Curve, FrostError};

pub mod coin;
use coin::{Coin, CoinError};
mod wallet;

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

// Generate a static view key for a given chain in a globally consistent manner
// Doesn't consider the current group key to increase the simplicity of verifying Serai's status
// Takes an index, k, for more modern privacy protocols which use multiple view keys
pub fn view_key<C: Coin>(k: u64) -> <C::Curve as Curve>::F {
    C::Curve::hash_to_F(b"Serai DEX View Key", &[C::ID, &k.to_le_bytes()].concat())
}
