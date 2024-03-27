use std::sync::Arc;

use ethers_core::{
  types::{U256, H160, Topic, Bytes, Transaction},
  utils::hex::FromHex,
};
use ethers_providers::{StreamExt, Middleware, Provider, Http};
use ethers_contract::ContractCall;

use crate::{
  Error, TransactionRequest,
  crypto::{self, keccak256, PublicKey},
  router::Router,
};
pub use crate::abi::deployer as abi;

/// The Deployer contract for the Router contract.
///
/// This Deployer has a deterministic address, letting it be immediately identified on any
/// compatible chain. It then supports retrieving the Router contract's address (which isn't
/// deterministic) using a single log query.
#[derive(Clone, Debug)]
pub struct Deployer(abi::Deployer<Provider<Http>>);
impl Deployer {
  /// Obtain the transaction to deploy this contract, already signed.
  ///
  /// The account this transaction is sent from (which is populated in `from`) must be sufficiently
  /// funded for this transaction to be submitted. This account has no known private key to anyone,
  /// so ETH sent can be neither misappropriated nor returned.
  pub fn deployment_tx(chain_id: u64) -> Result<Transaction, Error> {
    let bytecode = include_str!("../artifacts/Deployer.bin");
    let bytecode =
      Bytes::from_hex(bytecode).expect("compiled-in Deployer bytecode wasn't valid hex");

    let tx_request = TransactionRequest {
      from: None,
      to: None,
      // TODO. This is a fine default yet it should be much more accurate to minimize waste
      gas: Some(1_000_000u64.into()),
      // 100 gwei
      gas_price: Some(100_000_000_000u64.into()),
      value: Some(U256::zero()),
      data: Some(bytecode),
      nonce: Some(U256::zero()),
      chain_id: Some(chain_id.into()),
    };

    crypto::deterministically_sign(chain_id, &tx_request)
  }

  /// Obtain the deterministic address for this contract.
  pub fn address(chain_id: u64) -> Result<[u8; 20], Error> {
    let deployer_deployer = Self::deployment_tx(chain_id)?.from;
    Ok(ethers_core::utils::get_contract_address(deployer_deployer, U256::zero()).0)
  }

  /// Construct a new view of the `Deployer`.
  pub async fn new(provider: Arc<Provider<Http>>) -> Result<Option<Self>, Error> {
    let chain_id = provider.get_chainid().await.map_err(|_| Error::ConnectionError)?;
    if chain_id > U256::from(u64::MAX) {
      Err(Error::ChainIdExceedsBounds)?;
    }
    let address = Self::address(chain_id.as_u64())?;
    let code = provider.get_code(H160(address), None).await.map_err(|_| Error::ConnectionError)?;
    // Contract has yet to be deployed
    if code.is_empty() {
      return Ok(None);
    }
    Ok(Some(Self(abi::Deployer::new(address, provider))))
  }

  /// Yield the `ContractCall` necessary to deploy the Router.
  pub fn deploy_router(&self, key: &PublicKey) -> ContractCall<Provider<Http>, ()> {
    self.0.deploy(Router::init_code(key).into()).gas(1_000_000)
  }

  /// Find the first Router deployed with the specified key as its first key.
  ///
  /// This is the Router Serai will use, and is the only way to construct a `Router`.
  pub async fn find_router(
    &self,
    provider: Arc<Provider<Http>>,
    key: &PublicKey,
  ) -> Result<Option<Router>, Error> {
    let init_code = Router::init_code(key);
    let init_code_hash = keccak256(&init_code);

    // Find the first log using this init code (where the init code is binding to the key)
    let mut filter = self.0.deployment_filter().filter.from_block(0);
    filter.topics[1] = Some(Topic::Value(Some(init_code_hash.into())));

    let Some(logs) = provider.get_logs_paginated(&filter, 1).next().await else { return Ok(None) };
    let first_log = logs.map_err(|_| Error::ConnectionError)?;

    // Read the address from its data
    if (first_log.data.len() != 32) || (first_log.data[.. 12] != [0; 12]) {
      Err(Error::ConnectionError)?;
    }
    let mut router = [0; 20];
    router.copy_from_slice(&first_log.data[12 ..]);

    Ok(Some(Router::new(provider, router)))
  }
}
