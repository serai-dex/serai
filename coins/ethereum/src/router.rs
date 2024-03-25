use std::sync::Arc;

use group::ff::PrimeField;

use ethers_core::types::U256;
use ethers_providers::{Provider, Http};
use ethers_contract::ContractCall;

pub use crate::{
  Error,
  crypto::{PublicKey, Signature},
  abi::router as abi,
};

#[derive(Clone, Debug)]
pub struct Router(abi::Router<Provider<Http>>);
impl Router {
  pub fn new(provider: Arc<Provider<Http>>, address: [u8; 20]) -> Self {
    Self(abi::Router::new(address, provider))
  }
  pub fn initialize(&self, public_key: &PublicKey) -> ContractCall<Provider<Http>, ()> {
    self.0.initialize(public_key.px.to_repr().into()).gas(100_000)
  }
  pub fn update_serai_key(&self) -> ContractCall<Provider<Http>, ()> {
    todo!()
  }
  pub async fn nonce(&self) -> Result<U256, Error> {
    self.0.nonce().call().await.map_err(|_| Error::ConnectionError)
  }
  pub fn execute(
    &self,
    outs: Vec<abi::OutInstruction>,
    sig: &Signature,
  ) -> ContractCall<Provider<Http>, ()> {
    let sig = abi::Signature { c: sig.c.to_repr().into(), s: sig.s.to_repr().into() };
    let gas = 100_000 + ((200_000 + 10_000) * outs.len());
    self.0.execute(outs, sig).gas(gas)
  }
}

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
