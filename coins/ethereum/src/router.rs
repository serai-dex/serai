use std::sync::Arc;

use ethers_core::{
  types::{BigEndianHash, H256, U256, Bytes},
  utils::hex::FromHex,
  abi::{self as eth_abi, AbiEncode},
};
use ethers_providers::{Provider, Http};
use ethers_contract::ContractCall;

pub use crate::{
  Error,
  crypto::{PublicKey, Signature},
  abi::router as abi,
};

/// The contract Serai uses to manage its state.
#[derive(Clone, Debug)]
pub struct Router(pub(crate) abi::Router<Provider<Http>>);
impl Router {
  pub(crate) fn code() -> Vec<u8> {
    let bytecode = include_str!("../artifacts/Router.bin");
    Bytes::from_hex(bytecode).expect("compiled-in Router bytecode wasn't valid hex").to_vec()
  }

  pub(crate) fn init_code(key: &PublicKey) -> Vec<u8> {
    let bytecode = Router::code();

    // Append the constructor arguments
    eth_abi::encode_packed(&[
      eth_abi::Token::Bytes(bytecode.as_slice().to_vec()),
      eth_abi::Token::Bytes(key.eth_repr().encode()),
    ])
    .unwrap()
  }

  // This isn't pub in order to force users to use `Deployer::find_router`.
  pub(crate) fn new(provider: Arc<Provider<Http>>, address: [u8; 20]) -> Self {
    Self(abi::Router::new(address, provider))
  }

  /// Get the current key for Serai.
  pub async fn serai_key(&self) -> Result<PublicKey, Error> {
    self
      .0
      .serai_key()
      .call()
      .await
      .ok()
      .and_then(PublicKey::from_eth_repr)
      .ok_or(Error::ConnectionError)
  }

  /// Get the message to be signed in order to update the key for Serai.
  pub fn update_serai_key_message(chain_id: U256, key: &PublicKey) -> Vec<u8> {
    [b"updateSeraiKey".as_slice(), &H256::from_uint(&chain_id).0, &key.eth_repr()].concat()
  }

  /// Update the key representing Serai.
  pub fn update_serai_key(
    &self,
    public_key: &PublicKey,
    sig: &Signature,
  ) -> ContractCall<Provider<Http>, ()> {
    // TODO: Set a saner gas
    self.0.update_serai_key(public_key.eth_repr(), sig.into()).gas(100_000)
  }

  /// Get the current nonce for the published batches.
  pub async fn nonce(&self) -> Result<U256, Error> {
    self.0.nonce().call().await.map_err(|_| Error::ConnectionError)
  }

  /// Get the message to be signed in order to update the key for Serai.
  pub fn execute_message(chain_id: U256, nonce: U256, outs: Vec<abi::OutInstruction>) -> Vec<u8> {
    ("execute".to_string(), chain_id, nonce, outs).encode()
  }

  /// Execute a batch of `OutInstruction`s.
  pub fn execute(
    &self,
    outs: Vec<abi::OutInstruction>,
    sig: &Signature,
  ) -> ContractCall<Provider<Http>, ()> {
    let gas = 100_000 + ((200_000 + 10_000) * outs.len()); // TODO
    self.0.execute(outs, sig.into()).gas(gas)
  }
}
