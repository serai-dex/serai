use std::sync::Arc;

use ethers_core::{
  types::{U256, H160},
  abi::{AbiEncode, AbiDecode},
};
use ethers_providers::{Middleware, Provider, Http};
use ethers_contract::EthLogDecode;

use crate::Error;
pub use crate::abi::erc20 as abi;
use abi::{ERC20Calls, TransferFilter};

#[derive(Clone, Debug)]
pub struct TopLevelErc20Transfer {
  pub id: [u8; 32],
  pub from: [u8; 20],
  pub amount: U256,
  pub data: Vec<u8>,
}

/// A view for an ERC20 contract.
#[derive(Clone, Debug)]
pub struct ERC20(Arc<Provider<Http>>, [u8; 20], abi::ERC20<Provider<Http>>);
impl ERC20 {
  /// Construct a new view of the specified ERC20 contract.
  ///
  /// This checks a contract is deployed at that address yet does not check the contract is
  /// actually an ERC20.
  pub async fn new(
    provider: Arc<Provider<Http>>,
    address: [u8; 20],
  ) -> Result<Option<Self>, Error> {
    let chain_id = provider.get_chainid().await.map_err(|_| Error::ConnectionError)?;
    if chain_id > U256::from(u64::MAX) {
      Err(Error::ChainIdExceedsBounds)?;
    }
    let code = provider.get_code(H160(address), None).await.map_err(|_| Error::ConnectionError)?;
    // Contract has yet to be deployed
    if code.is_empty() {
      return Ok(None);
    }
    Ok(Some(Self(provider.clone(), address, abi::ERC20::new(address, provider))))
  }

  pub async fn top_level_transfers(
    &self,
    block: u64,
    to: [u8; 20],
  ) -> Result<Vec<TopLevelErc20Transfer>, Error> {
    let mut to_topic = [0; 32];
    to_topic[12 ..].copy_from_slice(&to);
    let filter = self.2.transfer_filter().filter;
    let filter = filter.from_block(block).to_block(block);
    let filter = filter.topic2(ethers_core::types::ValueOrArray::Value(Some(to_topic.into())));
    let logs = self.0.get_logs(&filter).await.map_err(|_| Error::ConnectionError)?;

    let mut top_level_transfers = vec![];
    for log in logs {
      // Double check the address which emitted this log
      if log.address.0 != self.1 {
        Err(Error::ConnectionError)?;
      }

      let tx = self
        .0
        .get_transaction(log.transaction_hash.ok_or(Error::ConnectionError)?)
        .await
        .map_err(|_| Error::ConnectionError)?
        .ok_or(Error::ConnectionError)?;

      // If this is a top-level call...
      if tx.to == Some(self.1.into()) {
        // And we recognize the call...
        if let Ok(call) = ERC20Calls::decode(&tx.input) {
          // Get the ID for this log
          let id = log.transaction_hash.ok_or(Error::ConnectionError)?.into();

          // Read the data appended after
          let encoded = call.encode();
          let data = tx.input.as_ref()[encoded.len() ..].to_vec();

          let log = TransferFilter::decode_log(&log.into()).map_err(|_| Error::ConnectionError)?;
          // Push the transfer
          top_level_transfers.push(TopLevelErc20Transfer {
            id,
            from: log.from.0,
            amount: log.value,
            data,
          });
        }
      }
    }
    Ok(top_level_transfers)
  }
}
