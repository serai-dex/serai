use std::fmt::Debug;

use thiserror::Error;

use hex::ToHex;

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};

use monero::{
  Hash,
  blockdata::{
    transaction::Transaction,
    block::Block
  },
  consensus::encode::{serialize, deserialize}
};

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::json;

use reqwest;

#[derive(Deserialize, Debug)]
struct EmptyResponse {}
#[derive(Deserialize, Debug)]
struct JsonRpcResponse<T> {
  result: T
}

#[derive(Error, Debug)]
pub enum RpcError {
  #[error("internal error ({0})")]
  InternalError(String),
  #[error("connection error")]
  ConnectionError,
  #[error("transaction not found (expected {1}, got {0})")]
  TransactionsNotFound(usize, usize),
  #[error("invalid point ({0})")]
  InvalidPoint(String),
  #[error("invalid transaction")]
  InvalidTransaction
}

fn rpc_hex(value: &str) -> Result<Vec<u8>, RpcError> {
  hex::decode(value).map_err(|_| RpcError::InternalError("Monero returned invalid hex".to_string()))
}

fn rpc_point(point: &str) -> Result<EdwardsPoint, RpcError> {
  CompressedEdwardsY(
    rpc_hex(point)?.try_into().map_err(|_| RpcError::InvalidPoint(point.to_string()))?
  ).decompress().ok_or(RpcError::InvalidPoint(point.to_string()))
}

pub struct Rpc(String);

impl Rpc {
  pub fn new(daemon: String) -> Rpc {
    Rpc(daemon)
  }

  async fn rpc_call<
    Params: Serialize + Debug,
    Response: DeserializeOwned + Debug
  >(&self, method: &str, params: Option<Params>) -> Result<Response, RpcError> {
    let client = reqwest::Client::new();
    let mut builder = client.post(&(self.0.clone() + "/" + method));
    if let Some(params) = params.as_ref() {
      builder = builder.json(params);
    }

    self.call_tail(method, builder).await
  }

  async fn bin_call<
    Response: DeserializeOwned + Debug
  >(&self, method: &str, params: Vec<u8>) -> Result<Response, RpcError> {
    let client = reqwest::Client::new();
    let builder = client.post(&(self.0.clone() + "/" + method)).body(params);
    self.call_tail(method, builder.header("Content-Type", "application/octet-stream")).await
  }

  async fn call_tail<
    Response: DeserializeOwned + Debug
  >(&self, method: &str, builder: reqwest::RequestBuilder) -> Result<Response, RpcError> {
    let res = builder
      .send()
      .await
      .map_err(|_| RpcError::ConnectionError)?;

    Ok(
      if !method.ends_with(".bin") {
        serde_json::from_str(&res.text().await.map_err(|_| RpcError::ConnectionError)?)
          .map_err(|_| RpcError::InternalError("Failed to parse json response".to_string()))?
      } else {
        monero_epee_bin_serde::from_bytes(&res.bytes().await.map_err(|_| RpcError::ConnectionError)?)
          .map_err(|_| RpcError::InternalError("Failed to parse binary response".to_string()))?
      }
    )
  }

  pub async fn get_height(&self) -> Result<usize, RpcError> {
    #[derive(Deserialize, Debug)]
    struct HeightResponse {
      height: usize
    }
    Ok(self.rpc_call::<Option<()>, HeightResponse>("get_height", None).await?.height)
  }

  pub async fn get_transactions(&self, hashes: Vec<Hash>) -> Result<Vec<Transaction>, RpcError> {
    #[derive(Deserialize, Debug)]
    struct TransactionResponse {
      as_hex: String
    }
    #[derive(Deserialize, Debug)]
    struct TransactionsResponse {
      txs: Vec<TransactionResponse>
    }

    let txs: TransactionsResponse = self.rpc_call("get_transactions", Some(json!({
      "txs_hashes": hashes.iter().map(|hash| hash.encode_hex()).collect::<Vec<String>>()
    }))).await?;
    if txs.txs.len() != hashes.len() {
      Err(RpcError::TransactionsNotFound(txs.txs.len(), hashes.len()))?;
    }

    let mut res = Vec::with_capacity(txs.txs.len());
    for tx in txs.txs {
      res.push(
        deserialize(
          &rpc_hex(&tx.as_hex)?
        ).expect("Monero returned a transaction we couldn't deserialize")
      );
    }
    Ok(res)
  }

  pub async fn get_block_transactions(&self, height: usize) -> Result<Vec<Transaction>, RpcError> {
    #[derive(Deserialize, Debug)]
    struct BlockResponse {
      blob: String
    }

    let block: JsonRpcResponse<BlockResponse> = self.rpc_call("json_rpc", Some(json!({
      "method": "get_block",
      "params": {
        "height": height
      }
    }))).await?;

    let block: Block = deserialize(
      &rpc_hex(&block.result.blob)?
    ).expect("Monero returned a block we couldn't deserialize");

    let mut res = vec![block.miner_tx];
    if block.tx_hashes.len() != 0 {
      res.extend(self.get_transactions(block.tx_hashes).await?);
    }
    Ok(res)
  }

  pub async fn get_o_indexes(&self, hash: Hash) -> Result<Vec<u64>, RpcError> {
    #[derive(Serialize, Debug)]
    struct Request {
      txid: [u8; 32]
    }

    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct OIndexes {
      o_indexes: Vec<u64>,
      status: String,
      untrusted: bool,
      credits: usize,
      top_hash: String
    }

    let indexes: OIndexes = self.bin_call("get_o_indexes.bin", monero_epee_bin_serde::to_bytes(
      &Request {
        txid: hash.0
      }).expect("Couldn't serialize a request")
    ).await?;

    Ok(indexes.o_indexes)
  }

  pub async fn get_ring(&self, mixins: &[u64]) -> Result<Vec<[EdwardsPoint; 2]>, RpcError> {
    #[derive(Deserialize, Debug)]
    struct Out {
      key: String,
      mask: String
    }

    #[derive(Deserialize, Debug)]
    struct Outs {
      outs: Vec<Out>
    }

    let outs: Outs = self.rpc_call("get_outs", Some(json!({
      "outputs": mixins.iter().map(|m| json!({
        "amount": 0,
        "index": m
      })).collect::<Vec<_>>()
    }))).await?;

    let mut res = vec![];
    for out in outs.outs {
      res.push([rpc_point(&out.key)?, rpc_point(&out.mask)?]);
    }
    Ok(res)
  }

  pub async fn publish_transaction(&self, tx: &Transaction) -> Result<(), RpcError> {
    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct SendRawResponse {
      status: String,
      double_spend: bool,
      fee_too_low: bool,
      invalid_input: bool,
      invalid_output: bool,
      low_mixin: bool,
      not_relayed: bool,
      overspend: bool,
      too_big: bool,
      too_few_outputs: bool,
      reason: String
    }

    let res: SendRawResponse = self.rpc_call("send_raw_transaction", Some(json!({
      "tx_as_hex": hex::encode(&serialize(tx))
    }))).await?;

    if res.status != "OK" {
      Err(RpcError::InvalidTransaction)?;
    }

    Ok(())
  }

  #[cfg(test)]
  pub async fn mine_block(&self, address: String) -> Result<(), RpcError> {
    let _: EmptyResponse = self.rpc_call("json_rpc", Some(json!({
      "jsonrpc": "2.0",
      "id": (),
      "method": "generateblocks",
      "params": {
        "wallet_address": address,
        "amount_of_blocks": 10
      },
    }))).await?;
    Ok(())
  }
}
