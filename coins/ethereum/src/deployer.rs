use std::sync::Arc;

use ethers_core::{
  types::{BigEndianHash, U256, H160, Topic, Bytes, Transaction},
  utils::{hex::FromHex, rlp},
};
use ethers_providers::{StreamExt, Middleware, Provider, Http};
use ethers_contract::ContractCall;

use crate::{
  Error, TransactionRequest,
  crypto::{self, keccak256, PublicKey},
  router::Router,
};
pub use crate::abi::deployer as abi;

#[derive(Clone, Debug)]
pub struct Deployer(abi::Deployer<Provider<Http>>);
impl Deployer {
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

  pub fn address(chain_id: u64) -> Result<[u8; 20], Error> {
    let deployer_deployer = Self::deployment_tx(chain_id)?.from;

    let mut address = [0; 20];
    address.copy_from_slice(
      &{
        let mut stream = rlp::RlpStream::new_list(2);
        stream.append(&deployer_deployer);
        stream.append(&U256::zero());
        keccak256(stream.as_raw())
      }[12 ..],
    );
    Ok(address)
  }

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

  pub async fn nonce(&self) -> Result<U256, Error> {
    self.0.nonce().call().await.map_err(|_| Error::ConnectionError)
  }

  pub fn deploy_router(&self, key: &PublicKey) -> ContractCall<Provider<Http>, ()> {
    self.0.deploy(Router::init_code(key).into()).gas(1_000_000)
  }

  pub fn deployment_address(
    chain_id: u64,
    nonce: U256,
    init_code_hash: [u8; 32],
  ) -> Result<[u8; 20], Error> {
    let mut nonce_bytes = [0; 32];
    nonce.to_big_endian(&mut nonce_bytes);

    // CREATE2 derivation
    Ok(
      keccak256(
        &[[0xff].as_slice(), &Self::address(chain_id)?, &nonce_bytes, &init_code_hash].concat(),
      )[12 ..]
        .try_into()
        .unwrap(),
    )
  }

  pub async fn find_router(
    &self,
    provider: &Arc<Provider<Http>>,
    key: &PublicKey,
  ) -> Result<Option<[u8; 20]>, Error> {
    let chain_id = provider.get_chainid().await.map_err(|_| Error::ConnectionError)?;
    if chain_id > U256::from(u64::MAX) {
      Err(Error::ChainIdExceedsBounds)?;
    }
    let chain_id = chain_id.as_u64();

    let init_code_hash = keccak256(&Router::init_code(key));

    let mut filter = self.0.deployment_filter().filter.from_block(0);
    filter.topics[2] = Some(Topic::Value(Some(init_code_hash.into())));

    let Some(logs) = provider.get_logs_paginated(&filter, 1).next().await else { return Ok(None) };
    let first_log = logs.map_err(|_| Error::ConnectionError)?;
    let nonce = first_log.topics[1];

    if (first_log.data.len() != 32) || (first_log.data[.. 12] != [0; 12]) {
      Err(Error::ConnectionError)?;
    }
    let mut router = [0; 20];
    router.copy_from_slice(&first_log.data[12 ..]);
    if router != Self::deployment_address(chain_id, nonce.into_uint(), init_code_hash)? {
      Err(Error::ConnectionError)?;
    }
    Ok(Some(router))
  }
}
