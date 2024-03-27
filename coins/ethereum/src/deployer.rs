use std::sync::Arc;

use ethers_core::{
  types::{U256, H160, Bytes, Transaction},
  utils::{hex::FromHex, rlp},
  abi::{self as eth_abi, AbiEncode},
};
use ethers_providers::{Middleware, Provider, Http};
use ethers_contract::ContractCall;

use crate::{
  Error, TransactionRequest,
  crypto::{self, keccak256, PublicKey},
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

  pub async fn new(provider: Arc<Provider<Http>>) -> Result<Option<Self>, Error> {
    let chain_id = provider.get_chainid().await.map_err(|_| Error::ConnectionError)?;
    if chain_id > U256::from(u64::MAX) {
      Err(Error::ChainIdExceedsBounds)?;
    }
    let deployer_deployer = Self::deployment_tx(chain_id.as_u64())?.from;

    let mut address = [0; 20];
    address.copy_from_slice(
      &{
        let mut stream = rlp::RlpStream::new_list(2);
        stream.append(&deployer_deployer);
        stream.append(&U256::zero());
        keccak256(stream.as_raw())
      }[12 ..],
    );

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

  pub(crate) fn router_init_code(key: &PublicKey) -> Vec<u8> {
    let bytecode = include_str!("../artifacts/Router.bin");
    let bytecode = Bytes::from_hex(bytecode).expect("compiled-in Router bytecode wasn't valid hex");

    // Append the constructor arguments
    eth_abi::encode_packed(&[
      eth_abi::Token::Bytes(bytecode.as_ref().to_vec()),
      eth_abi::Token::Bytes(key.eth_repr().encode()),
    ])
    .unwrap()
  }

  pub fn deploy_router(&self, key: &PublicKey) -> ContractCall<Provider<Http>, ()> {
    self.0.deploy(Self::router_init_code(key).into()).gas(1_000_000)
  }
}
