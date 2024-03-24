use crate::{crypto::ProcessedSignature, errors::EthereumError};
use ethers::{contract::ContractFactory, prelude::*, solc::artifacts::contract::ContractBytecode};
use eyre::{eyre, Result};
use std::fs::File;
use std::sync::Arc;

abigen!(
  Schnorr,
  "./artifacts/Schnorr.sol/Schnorr.json",
  event_derives(serde::Deserialize, serde::Serialize),
);

pub async fn deploy_schnorr_verifier_contract(
  client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
) -> Result<schnorr_mod::Schnorr<SignerMiddleware<Provider<Http>, LocalWallet>>> {
  let path = "./artifacts/Schnorr.sol/Schnorr.json";
  let artifact: ContractBytecode = serde_json::from_reader(File::open(path).unwrap()).unwrap();
  let abi = artifact.abi.unwrap();
  let bin = artifact.bytecode.unwrap().object;
  let factory = ContractFactory::new(abi, bin.into_bytes().unwrap(), client.clone());
  let contract = factory.deploy(())?.send().await?;
  let contract = Schnorr::new(contract.address(), client);
  Ok(contract)
}

pub async fn call_verify(
  contract: &schnorr_mod::Schnorr<SignerMiddleware<Provider<Http>, LocalWallet>>,
  params: &ProcessedSignature,
) -> Result<()> {
  if contract
    .verify(
      params.public_key.parity,
      params.public_key.px.to_bytes().into(),
      params.message,
      params.e.to_bytes().into(),
      params.s.to_bytes().into(),
    )
    .call()
    .await?
  {
    Ok(())
  } else {
    Err(eyre!(EthereumError::VerificationError))
  }
}
