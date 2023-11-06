use std::{sync::Arc, fs::File};

use thiserror::Error;
use eyre::{eyre, Result};

use ethers_signers::LocalWallet;
use ethers_middleware::SignerMiddleware;
use ethers_providers::{Provider, Http};
use ethers_contract::{abigen, ContractFactory};
use ethers_solc::artifacts::contract::ContractBytecode;

use crate::crypto::ProcessedSignature;

#[derive(Error, Debug)]
pub enum EthereumError {
  #[error("failed to verify Schnorr signature")]
  VerificationError,
}

abigen!(Schnorr, "./artifacts/Schnorr.sol/Schnorr.json");

pub async fn call_verify(
  contract: &Schnorr<SignerMiddleware<Provider<Http>, LocalWallet>>,
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
