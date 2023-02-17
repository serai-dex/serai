use core::fmt::Debug;

use thiserror::Error;

use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;

use bitcoin::{
  hashes::{
    Hash,
    hex::{FromHex, ToHex},
  },
  consensus::encode,
  Txid, Transaction, BlockHash, Block,
};

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum RpcResponse<T> {
  Ok { result: T },
  Err { error: String },
}

#[derive(Clone, Debug)]
pub struct Rpc(String);

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum RpcError {
  #[error("couldn't connect to node")]
  ConnectionError,
  #[error("request had an error: {0}")]
  RequestError(String),
  #[error("node sent an invalid response")]
  InvalidResponse,
}

impl Rpc {
  pub fn new(url: String) -> Rpc {
    Rpc(url)
  }

  pub async fn rpc_call<Response: DeserializeOwned + Debug>(
    &self,
    method: &str,
    params: serde_json::Value,
  ) -> Result<Response, RpcError> {
    let client = reqwest::Client::new();
    let res = client
      .post(&self.0)
      .json(&json!({ "jsonrpc": "2.0", "method": method, "params": params }))
      .send()
      .await
      .map_err(|_| RpcError::ConnectionError)?
      .text()
      .await
      .map_err(|_| RpcError::ConnectionError)?;

    let res: RpcResponse<Response> =
      serde_json::from_str(&res).map_err(|_| RpcError::InvalidResponse)?;
    match res {
      RpcResponse::Ok { result } => Ok(result),
      RpcResponse::Err { error } => Err(RpcError::RequestError(error)),
    }
  }

  pub async fn get_latest_block_number(&self) -> Result<usize, RpcError> {
    self.rpc_call("getblockcount", json!([])).await
  }

  pub async fn get_block_hash(&self, number: usize) -> Result<[u8; 32], RpcError> {
    let mut hash =
      self.rpc_call::<BlockHash>("getblockhash", json!([number])).await?.as_hash().into_inner();
    hash.reverse();
    Ok(hash)
  }

  pub async fn get_block_number(&self, hash: &[u8; 32]) -> Result<usize, RpcError> {
    #[derive(Deserialize, Debug)]
    struct Number {
      height: usize,
    }
    Ok(self.rpc_call::<Number>("getblockheader", json!([hash.to_hex()])).await?.height)
  }

  pub async fn get_block(&self, hash: &[u8; 32]) -> Result<Block, RpcError> {
    let hex = self.rpc_call::<String>("getblock", json!([hash.to_hex(), 0])).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex).map_err(|_| RpcError::InvalidResponse)?;
    encode::deserialize(&bytes).map_err(|_| RpcError::InvalidResponse)
  }

  pub async fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, RpcError> {
    self.rpc_call("sendrawtransaction", json!([encode::serialize_hex(tx)])).await
  }

  pub async fn get_transaction(&self, hash: &[u8; 32]) -> Result<Transaction, RpcError> {
    let hex = self.rpc_call::<String>("getrawtransaction", json!([hash.to_hex()])).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex).map_err(|_| RpcError::InvalidResponse)?;
    encode::deserialize(&bytes).map_err(|_| RpcError::InvalidResponse)
  }
}
