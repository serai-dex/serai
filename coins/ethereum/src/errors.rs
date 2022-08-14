use thiserror::Error;

#[derive(Error, Debug)]
pub enum EthereumError {
  #[error("failed to verify Schnorr signature")]
  VerificationError,
}
