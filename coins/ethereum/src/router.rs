pub use crate::abi::router::*;

/*
use crate::crypto::{ProcessedSignature, PublicKey};
use ethers::{contract::ContractFactory, prelude::*, solc::artifacts::contract::ContractBytecode};
use eyre::Result;
use std::{convert::From, fs::File, sync::Arc};

pub async fn router_update_public_key<M: Middleware + 'static>(
  contract: &Router<M>,
  public_key: &PublicKey,
  signature: &ProcessedSignature,
) -> std::result::Result<Option<TransactionReceipt>, eyre::ErrReport> {
  let tx = contract.update_public_key(public_key.px.to_bytes().into(), signature.into());
  let pending_tx = tx.send().await?;
  let receipt = pending_tx.await?;
  Ok(receipt)
}

pub async fn router_execute<M: Middleware + 'static>(
  contract: &Router<M>,
  txs: Vec<Rtransaction>,
  signature: &ProcessedSignature,
) -> std::result::Result<Option<TransactionReceipt>, eyre::ErrReport> {
  let tx = contract.execute(txs, signature.into()).send();
  let pending_tx = tx.send().await?;
  let receipt = pending_tx.await?;
  Ok(receipt)
}
*/
