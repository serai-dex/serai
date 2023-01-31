use core::fmt::Debug;

use thiserror::Error;

use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;

use bitcoin::{
  hashes::hex::{FromHex, ToHex},
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

  pub async fn get_block_hash(&self, number: usize) -> Result<BlockHash, RpcError> {
    self.rpc_call("getblockhash", json!([number])).await
  }

  pub async fn get_block(&self, block_hash: &BlockHash) -> Result<Block, RpcError> {
    let hex = self.rpc_call::<String>("getblock", json!([block_hash.to_hex(), 0])).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex).map_err(|_| RpcError::InvalidResponse)?;
    encode::deserialize(&bytes).map_err(|_| RpcError::InvalidResponse)
  }

  pub async fn get_transaction(
    &self,
    txid: &Txid,
    block_hash: Option<&BlockHash>,
  ) -> Result<Transaction, RpcError> {
    let hex = self
      .rpc_call::<String>(
        "getrawtransaction",
        json!([txid.to_hex(), false, block_hash.map(|hash| hash.to_hex())]),
      )
      .await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex).map_err(|_| RpcError::InvalidResponse)?;
    encode::deserialize(&bytes).map_err(|_| RpcError::InvalidResponse)
  }

  pub async fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, RpcError> {
    self.rpc_call("sendrawtransaction", json!([encode::serialize_hex(tx)])).await
  }
}
