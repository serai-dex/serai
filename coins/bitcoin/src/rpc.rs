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
enum RpcResponse<T> {
  Ok { result: T },
  Err { error: String },
}

/// A minimal asynchronous Bitcoin RPC client.
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
  pub async fn new(url: String) -> Result<Rpc, RpcError> {
    let rpc = Rpc(url);
    // Make an RPC request to verify the node is reachable and sane
    rpc.get_latest_block_number().await?;
    Ok(rpc)
  }

  /// Perform an arbitrary RPC call.
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

  /// Get the latest block's number.
  pub async fn get_latest_block_number(&self) -> Result<usize, RpcError> {
    self.rpc_call("getblockcount", json!([])).await
  }

  /// Get the hash of a block by the block's number.
  pub async fn get_block_hash(&self, number: usize) -> Result<[u8; 32], RpcError> {
    let mut hash =
      self.rpc_call::<BlockHash>("getblockhash", json!([number])).await?.as_hash().into_inner();
    // bitcoin stores the inner bytes in reverse order.
    hash.reverse();
    Ok(hash)
  }

  /// Get a block's number by its hash.
  pub async fn get_block_number(&self, hash: &[u8; 32]) -> Result<usize, RpcError> {
    #[derive(Deserialize, Debug)]
    struct Number {
      height: usize,
    }
    Ok(self.rpc_call::<Number>("getblockheader", json!([hash.to_hex()])).await?.height)
  }

  /// Get a block by its hash.
  pub async fn get_block(&self, hash: &[u8; 32]) -> Result<Block, RpcError> {
    let hex = self.rpc_call::<String>("getblock", json!([hash.to_hex(), 0])).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex).map_err(|_| RpcError::InvalidResponse)?;
    let block: Block = encode::deserialize(&bytes).map_err(|_| RpcError::InvalidResponse)?;

    let mut block_hash = block.block_hash().as_hash().into_inner();
    block_hash.reverse();
    if hash != &block_hash {
      Err(RpcError::InvalidResponse)?;
    }

    Ok(block)
  }

  /// Publish a transaction.
  pub async fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, RpcError> {
    let txid = self.rpc_call("sendrawtransaction", json!([encode::serialize_hex(tx)])).await?;
    if txid != tx.txid() {
      Err(RpcError::InvalidResponse)?;
    }
    Ok(txid)
  }

  /// Get a transaction by its hash.
  pub async fn get_transaction(&self, hash: &[u8; 32]) -> Result<Transaction, RpcError> {
    let hex = self.rpc_call::<String>("getrawtransaction", json!([hash.to_hex()])).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex).map_err(|_| RpcError::InvalidResponse)?;
    let tx: Transaction = encode::deserialize(&bytes).map_err(|_| RpcError::InvalidResponse)?;

    let mut tx_hash = tx.txid().as_hash().into_inner();
    tx_hash.reverse();
    if hash != &tx_hash {
      Err(RpcError::InvalidResponse)?;
    }

    Ok(tx)
  }
}
