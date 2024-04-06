use thiserror::Error;

pub use ethers_core;
pub use ethers_providers;
pub(crate) use ethers_core::types::transaction::request::TransactionRequest;

pub mod crypto;

pub(crate) mod abi;
pub mod erc20;
pub mod deployer;
pub mod router;

pub mod machine;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum Error {
  #[error("this chain has a chain ID exceeding the expected bounds")]
  ChainIdExceedsBounds,
  #[error("failed to verify Schnorr signature")]
  InvalidSignature,
  #[error("couldn't make call/send TX")]
  ConnectionError,
}
