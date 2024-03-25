use thiserror::Error;

pub mod crypto;

pub(crate) mod abi;
pub mod router;

#[cfg(test)]
mod tests;

#[derive(Error, Debug)]
pub enum Error {
  #[error("failed to verify Schnorr signature")]
  InvalidSignature,
  #[error("couldn't make call/send TX")]
  ConnectionError,
}
