use std::sync::Arc;

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

  /// Initialize the smart contract.
  pub fn initialize(&self, public_key: &PublicKey) -> ContractCall<Provider<Http>, ()> {
    self.0.initialize(public_key.eth_repr()).gas(100_000)
  }

  /// Update the key representing Serai.
  pub fn update_serai_key(
    &self,
    public_key: &PublicKey,
    sig: &Signature,
  ) -> ContractCall<Provider<Http>, ()> {
    self.0.update_serai_key(public_key.eth_repr(), sig.into()).gas(100_000)
  }

  /// Returns the current nonce for the published batches.
  pub async fn nonce(&self) -> Result<U256, Error> {
    self.0.nonce().call().await.map_err(|_| Error::ConnectionError)
  }

  /// Execute a batch of OutInstructions.
  pub fn execute(
    &self,
    outs: Vec<abi::OutInstruction>,
    sig: &Signature,
  ) -> ContractCall<Provider<Http>, ()> {
    let gas = 100_000 + ((200_000 + 10_000) * outs.len());
    self.0.execute(outs, sig.into()).gas(gas)
  }
}
