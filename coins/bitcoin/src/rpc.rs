use core::fmt::Debug;
use std::collections::HashSet;

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
  #[error("node replied with invalid JSON")]
  InvalidJson(serde_json::error::Category),
  #[error("node sent an invalid response ({0})")]
  InvalidResponse(&'static str),
  #[error("node was missing expected methods")]
  MissingMethods(HashSet<&'static str>),
}

impl Rpc {
  /// Create a new connection to a Bitcoin RPC.
  ///
  /// An RPC call is performed to ensure the node is reachable (and that an invalid URL wasn't
  /// provided).
  ///
  /// Additionally, a set of expected methods is checked to be offered by the Bitcoin RPC. If these
  /// methods aren't provided, an error with the missing methods is returned. This ensures all RPC
  /// routes explicitly provided by this library are at least possible.
  ///
  /// Each individual RPC route may still fail at time-of-call, regardless of the arguments
  /// provided to this library, if the RPC has an incompatible argument layout. That is not checked
  /// at time of RPC creation.
  pub async fn new(url: String) -> Result<Rpc, RpcError> {
    let rpc = Rpc { client: Client::new(), url };

    // Make an RPC request to verify the node is reachable and sane
    let res: String = rpc.rpc_call("help", json!([])).await?;

    // Verify all methods we expect are present
    // If we had a more expanded RPC, due to differences in RPC versions, it wouldn't make sense to
    // error if all methods weren't present
    // We only provide a very minimal set of methods which have been largely consistent, hence why
    // this is sane
    let mut expected_methods = HashSet::from([
      "help",
      "getblockcount",
      "getblockhash",
      "getblockheader",
      "getblock",
      "sendrawtransaction",
      "getrawtransaction",
    ]);
    for line in res.split('\n') {
      // This doesn't check if the arguments are as expected
      // This is due to Bitcoin supporting a large amount of optional arguments, which
      // occassionally change, with their own mechanism of text documentation, making matching off
      // it a quite involved task
      // Instead, once we've confirmed the methods are present, we assume our arguments are aligned
      // Else we'll error at time of call
      if expected_methods.remove(line.split(' ').next().unwrap_or("")) &&
        expected_methods.is_empty()
      {
        break;
      }
    }
    if !expected_methods.is_empty() {
      Err(RpcError::MissingMethods(expected_methods))?;
    };

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
      serde_json::from_str(&res).map_err(|e| RpcError::InvalidJson(e.classify()))?;
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
    let bytes: Vec<u8> = FromHex::from_hex(&hex)
      .map_err(|_| RpcError::InvalidResponse("node didn't use hex to encode the block"))?;
    let block: Block = encode::deserialize(&bytes)
      .map_err(|_| RpcError::InvalidResponse("node sent an improperly serialized block"))?;

    let mut block_hash = *block.block_hash().as_raw_hash().as_byte_array();
    block_hash.reverse();
    if hash != &block_hash {
      Err(RpcError::InvalidResponse("node replied with a different block"))?;
    }

    Ok(block)
  }

  /// Publish a transaction.
  pub async fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, RpcError> {
    let txid = self.rpc_call("sendrawtransaction", json!([encode::serialize_hex(tx)])).await?;
    if txid != tx.txid() {
      Err(RpcError::InvalidResponse("returned TX ID inequals calculated TX ID"))?;
    }
    Ok(txid)
  }

  /// Get a transaction by its hash.
  pub async fn get_transaction(&self, hash: &[u8; 32]) -> Result<Transaction, RpcError> {
    let hex = self.rpc_call::<String>("getrawtransaction", json!([hex::encode(hash)])).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex)
      .map_err(|_| RpcError::InvalidResponse("node didn't use hex to encode the transaction"))?;
    let tx: Transaction = encode::deserialize(&bytes)
      .map_err(|_| RpcError::InvalidResponse("node sent an improperly serialized transaction"))?;

    let mut tx_hash = *tx.txid().as_raw_hash().as_byte_array();
    tx_hash.reverse();
    if hash != &tx_hash {
      Err(RpcError::InvalidResponse("node replied with a different transaction"))?;
    }

    Ok(tx)
  }
}
