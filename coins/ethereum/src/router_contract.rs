use crate::crypto::{ProcessedSignature, PublicKey};
use ethers::{contract::ContractFactory, prelude::*, solc::artifacts::contract::ContractBytecode};
use eyre::Result;
use std::{convert::From, fs::File, sync::Arc};

abigen!(
  Router,
  "./artifacts/Router.sol/Router.json",
  event_derives(serde::Deserialize, serde::Serialize),
);

impl From<&PublicKey> for router_mod::PublicKey {
  fn from(public_key: &PublicKey) -> Self {
    router_mod::PublicKey { parity: public_key.parity, px: public_key.px.to_bytes().into() }
  }
}

impl From<&ProcessedSignature> for router_mod::Signature {
  fn from(signature: &ProcessedSignature) -> Self {
    router_mod::Signature { s: signature.s.to_bytes().into(), e: signature.e.to_bytes().into() }
  }
}

pub async fn deploy_router_contract(
  client: Arc<SignerMiddleware<Provider<Http>, LocalWallet>>,
) -> Result<router_mod::Router<SignerMiddleware<Provider<Http>, LocalWallet>>> {
  let path = "./artifacts/Router.sol/Router.json";
  let artifact: ContractBytecode = serde_json::from_reader(File::open(path).unwrap()).unwrap();
  let abi = artifact.abi.unwrap();
  let bin = artifact.bytecode.unwrap().object;
  let factory = ContractFactory::new(abi, bin.into_bytes().unwrap(), client.clone());
  let contract = factory.deploy(())?.send().await?;
  let contract = Router::new(contract.address(), client);
  Ok(contract)
}

pub async fn router_set_public_key(
  contract: &router_mod::Router<SignerMiddleware<Provider<Http>, LocalWallet>>,
  public_key: &PublicKey,
) -> std::result::Result<Option<TransactionReceipt>, eyre::ErrReport> {
  let tx = contract.set_public_key(public_key.into());
  let pending_tx = tx.send().await?;
  let receipt = pending_tx.await?;
  Ok(receipt)
}

pub async fn router_update_public_key(
  contract: &router_mod::Router<SignerMiddleware<Provider<Http>, LocalWallet>>,
  public_key: &PublicKey,
  signature: &ProcessedSignature,
) -> std::result::Result<Option<TransactionReceipt>, eyre::ErrReport> {
  let tx = contract.update_public_key(public_key.into(), signature.into());
  let pending_tx = tx.send().await?;
  let receipt = pending_tx.await?;
  Ok(receipt)
}

pub async fn router_execute(
  contract: &router_mod::Router<SignerMiddleware<Provider<Http>, LocalWallet>>,
  txs: Vec<router_mod::Transaction>,
  signature: &ProcessedSignature,
) -> std::result::Result<Option<TransactionReceipt>, eyre::ErrReport> {
  let tx = contract.execute(txs, signature.into());
  let pending_tx = tx.send().await?;
  let receipt = pending_tx.await?;
  Ok(receipt)
}
