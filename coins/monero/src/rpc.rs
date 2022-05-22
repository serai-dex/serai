use std::fmt::Debug;

use thiserror::Error;

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::json;

use reqwest;

use crate::{transaction::{Input, Transaction}, block::Block};

#[derive(Deserialize, Debug)]
pub struct EmptyResponse {}
#[derive(Deserialize, Debug)]
pub struct JsonRpcResponse<T> {
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
  #[error("pruned transaction")]
  PrunedTransaction,
  #[error("invalid transaction ({0:?})")]
  InvalidTransaction([u8; 32])
}

pub struct Rpc(String);

fn rpc_hex(value: &str) -> Result<Vec<u8>, RpcError> {
  hex::decode(value).map_err(|_| RpcError::InternalError("Monero returned invalid hex".to_string()))
}

fn rpc_point(point: &str) -> Result<EdwardsPoint, RpcError> {
  CompressedEdwardsY(
    rpc_hex(point)?.try_into().map_err(|_| RpcError::InvalidPoint(point.to_string()))?
  ).decompress().ok_or(RpcError::InvalidPoint(point.to_string()))
}

impl Rpc {
  pub fn new(daemon: String) -> Rpc {
    Rpc(daemon)
  }

  pub async fn rpc_call<
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

  pub async fn bin_call<
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
          .map_err(|_| RpcError::InternalError("Failed to parse JSON response".to_string()))?
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

  pub async fn get_transactions(&self, hashes: &[[u8; 32]]) -> Result<Vec<Transaction>, RpcError> {
    if hashes.len() == 0 {
      return Ok(vec![]);
    }

    #[derive(Deserialize, Debug)]
    struct TransactionResponse {
      as_hex: String,
      pruned_as_hex: String
    }
    #[derive(Deserialize, Debug)]
    struct TransactionsResponse {
      txs: Vec<TransactionResponse>
    }

    let txs: TransactionsResponse = self.rpc_call("get_transactions", Some(json!({
      "txs_hashes": hashes.iter().map(|hash| hex::encode(&hash)).collect::<Vec<String>>()
    }))).await?;
    if txs.txs.len() != hashes.len() {
      Err(RpcError::TransactionsNotFound(txs.txs.len(), hashes.len()))?;
    }

    txs.txs.iter().enumerate().map(|(i, res)| {
      let tx = Transaction::deserialize(
        &mut std::io::Cursor::new(
          rpc_hex(if res.as_hex.len() != 0 { &res.as_hex } else { &res.pruned_as_hex }).unwrap()
        )
      ).map_err(|_| RpcError::InvalidTransaction(hashes[i]))?;

      // https://github.com/monero-project/monero/issues/8311
      if res.as_hex.len() == 0 {
        match tx.prefix.inputs.get(0) {
          Some(Input::Gen { .. }) => (),
          _ => Err(RpcError::PrunedTransaction)?
        }
      }

      Ok(tx)
    }).collect::<Result<_, _>>()
  }

  pub async fn get_block(&self, height: usize) -> Result<Block, RpcError> {
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

    Ok(
      Block::deserialize(
        &mut std::io::Cursor::new(rpc_hex(&block.result.blob)?)
      ).expect("Monero returned a block we couldn't deserialize")
    )
  }

  pub async fn get_block_transactions(&self, height: usize) -> Result<Vec<Transaction>, RpcError> {
    let block = self.get_block(height).await?;
    let mut res = vec![block.miner_tx];
    res.extend(self.get_transactions(&block.txs).await?);
    Ok(res)
  }

  pub async fn get_o_indexes(&self, hash: [u8; 32]) -> Result<Vec<u64>, RpcError> {
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
        txid: hash
      }).unwrap()
    ).await?;

    Ok(indexes.o_indexes)
  }

  pub async fn get_outputs(
    &self,
    indexes: &[u64],
    height: usize
  ) -> Result<Vec<Option<[EdwardsPoint; 2]>>, RpcError> {
    #[derive(Deserialize, Debug)]
    pub struct Out {
      key: String,
      mask: String,
      txid: String
    }

    #[derive(Deserialize, Debug)]
    struct Outs {
      outs: Vec<Out>
    }

    let outs: Outs = self.rpc_call("get_outs", Some(json!({
      "get_txid": true,
      "outputs": indexes.iter().map(|o| json!({
        "amount": 0,
        "index": o
      })).collect::<Vec<_>>()
    }))).await?;

    let txs = self.get_transactions(
      &outs.outs.iter().map(|out|
        rpc_hex(&out.txid).expect("Monero returned an invalidly encoded hash")
          .try_into().expect("Monero returned an invalid sized hash")
      ).collect::<Vec<_>>()
    ).await?;
    // TODO: Support time based lock times. These shouldn't be needed, and it may be painful to
    // get the median time for the given height, yet we do need to in order to be complete
    outs.outs.iter().enumerate().map(
      |(i, out)| Ok(
        if txs[i].prefix.unlock_time <= u64::try_from(height).unwrap() {
          Some([rpc_point(&out.key)?, rpc_point(&out.mask)?])
        } else { None }
      )
    ).collect()
  }

  pub async fn get_output_distribution(&self, height: usize) -> Result<Vec<u64>, RpcError> {
    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    pub struct Distribution {
      distribution: Vec<u64>
    }

    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct Distributions {
      distributions: Vec<Distribution>
    }

    let mut distributions: JsonRpcResponse<Distributions> = self.rpc_call("json_rpc", Some(json!({
      "method": "get_output_distribution",
      "params": {
        "binary": false,
        "amounts": [0],
        "cumulative": true,
        "to_height": height
      }
    }))).await?;

    Ok(distributions.result.distributions.swap_remove(0).distribution)
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

    let mut buf = Vec::with_capacity(2048);
    tx.serialize(&mut buf).unwrap();
    let res: SendRawResponse = self.rpc_call("send_raw_transaction", Some(json!({
      "tx_as_hex": hex::encode(&buf)
    }))).await?;

    if res.status != "OK" {
      Err(RpcError::InvalidTransaction(tx.hash()))?;
    }

    Ok(())
  }
}
