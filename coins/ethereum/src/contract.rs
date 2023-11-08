use thiserror::Error;
use eyre::{eyre, Result};

use ethers_providers::{Provider, Http};
use ethers_contract::abigen;

use crate::crypto::ProcessedSignature;

#[derive(Error, Debug)]
pub enum EthereumError {
  #[error("failed to verify Schnorr signature")]
  VerificationError,
}

abigen!(Schnorr, "./artifacts/Schnorr.sol/Schnorr.json");

pub async fn call_verify(
  contract: &Schnorr<Provider<Http>>,
  params: &ProcessedSignature,
) -> Result<()> {
  if contract
    .verify(
      params.parity + 27,
      params.px.to_bytes().into(),
      params.message,
      params.s.to_bytes().into(),
      params.e.to_bytes().into(),
    )
    .call()
    .await?
  {
    Ok(())
  } else {
    Err(eyre!(EthereumError::VerificationError))
  }
}
