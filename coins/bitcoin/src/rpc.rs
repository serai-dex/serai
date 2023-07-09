use core::fmt::Debug;

use thiserror::Error;

use serde::{Deserialize, de::DeserializeOwned};
use serde_json::json;

use reqwest::Client;

use bitcoin::{
  hashes::{Hash, hex::FromHex},
  consensus::encode,
  Txid, Transaction, BlockHash, Block,
};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct Error {
  code: isize,
  message: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum RpcResponse<T> {
  Ok { result: T },
  Err { error: Error },
}

/// A minimal asynchronous Bitcoin RPC client.
#[derive(Clone, Debug)]
pub struct Rpc {
  client: Client,
  url: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum RpcError {
  #[error("couldn't connect to node")]
  ConnectionError,
  #[error("request had an error: {0:?}")]
  RequestError(Error),
  #[error("node sent an invalid response")]
  InvalidResponse,
}

impl Rpc {
  pub async fn new(url: String) -> Result<Rpc, RpcError> {
    let rpc = Rpc { client: Client::new(), url };
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
    let res = self
      .client
      .post(&self.url)
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
  ///
  /// The genesis block's 'number' is zero. They increment from there.
  pub async fn get_latest_block_number(&self) -> Result<usize, RpcError> {
    // getblockcount doesn't return the amount of blocks on the current chain, yet the "height"
    // of the current chain. The "height" of the current chain is defined as the "height" of the
    // tip block of the current chain. The "height" of a block is defined as the amount of blocks
    // present when the block was created. Accordingly, the genesis block has height 0, and
    // getblockcount will return 0 when it's only the only block, despite their being one block.
    self.rpc_call("getblockcount", json!([])).await
  }

  /// Get the hash of a block by the block's number.
  pub async fn get_block_hash(&self, number: usize) -> Result<[u8; 32], RpcError> {
    let mut hash = *self
      .rpc_call::<BlockHash>("getblockhash", json!([number]))
      .await?
      .as_raw_hash()
      .as_byte_array();
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
    Ok(self.rpc_call::<Number>("getblockheader", json!([hex::encode(hash)])).await?.height)
  }

  /// Get a block by its hash.
  pub async fn get_block(&self, hash: &[u8; 32]) -> Result<Block, RpcError> {
    let hex = self.rpc_call::<String>("getblock", json!([hex::encode(hash), 0])).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex).map_err(|_| RpcError::InvalidResponse)?;
    let block: Block = encode::deserialize(&bytes).map_err(|_| RpcError::InvalidResponse)?;

    let mut block_hash = *block.block_hash().as_raw_hash().as_byte_array();
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
    let hex = self.rpc_call::<String>("getrawtransaction", json!([hex::encode(hash)])).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex).map_err(|_| RpcError::InvalidResponse)?;
    let tx: Transaction = encode::deserialize(&bytes).map_err(|_| RpcError::InvalidResponse)?;

    let mut tx_hash = *tx.txid().as_raw_hash().as_byte_array();
    tx_hash.reverse();
    if hash != &tx_hash {
      Err(RpcError::InvalidResponse)?;
    }

    Ok(tx)
  }
}
