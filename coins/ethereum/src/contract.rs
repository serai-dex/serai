use crate::crypto::ProcessedSignature;
use ethers::{contract::ContractFactory, prelude::*};
use eyre::{eyre, Result};
use std::fs::File;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EthereumError {
    #[error("failed to verify Schnorr signature")]
    VerificationError,
}

abigen!(
    Schnorr,
    "./schnorr-verify/artifacts/contracts/Schnorr.sol/Schnorr.json",
    event_derives(serde::Deserialize, serde::Serialize),
);

pub async fn deploy_schnorr_verifier_contract(
    client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
) -> Result<schnorr_mod::Schnorr<SignerMiddleware<Provider<Http>, LocalWallet>>> {
    let path = "./schnorr-verify/artifacts/contracts/Schnorr.sol/Schnorr.json";
    let artifact: HardhatArtifact = serde_json::from_reader(File::open(path).unwrap()).unwrap();
    let (abi, bin, _) = artifact.into_parts();
    let factory = ContractFactory::new(abi.unwrap(), bin.unwrap(), client.clone());
    let contract = factory.deploy(())?.send().await?;
    let contract = Schnorr::new(contract.address(), client);
    Ok(contract)
}

pub async fn call_verify(
    contract: &schnorr_mod::Schnorr<SignerMiddleware<Provider<Http>, LocalWallet>>,
    params: &ProcessedSignature,
) -> Result<()> {
    let ok = contract
        .verify(
            params.sr.to_bytes().into(),
            params.er.to_bytes().into(),
            params.px.to_bytes().into(),
            params.parity + 27,
            params.message.into(),
            params.e.to_bytes().into(),
        )
        .call()
        .await?;
    if ok {
        Ok(())
    } else {
        Err(eyre!(EthereumError::VerificationError))
    }
}
