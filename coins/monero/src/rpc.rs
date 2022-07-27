use std::fmt::Debug;

use thiserror::Error;

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::json;

use reqwest;

use crate::{
  Protocol,
  transaction::{Input, Timelock, Transaction},
  block::Block,
  wallet::Fee,
};

#[derive(Deserialize, Debug)]
pub struct EmptyResponse {}
#[derive(Deserialize, Debug)]
pub struct JsonRpcResponse<T> {
  result: T,
}

#[derive(Clone, Error, Debug)]
pub enum RpcError {
  #[error("internal error ({0})")]
  InternalError(String),
  #[error("connection error")]
  ConnectionError,
  #[error("transactions not found")]
  TransactionsNotFound(Vec<[u8; 32]>),
  #[error("invalid point ({0})")]
  InvalidPoint(String),
  #[error("pruned transaction")]
  PrunedTransaction,
  #[error("invalid transaction ({0:?})")]
  InvalidTransaction([u8; 32]),
}

fn rpc_hex(value: &str) -> Result<Vec<u8>, RpcError> {
  hex::decode(value).map_err(|_| RpcError::InternalError("Monero returned invalid hex".to_string()))
}

fn rpc_point(point: &str) -> Result<EdwardsPoint, RpcError> {
  CompressedEdwardsY(
    rpc_hex(point)?.try_into().map_err(|_| RpcError::InvalidPoint(point.to_string()))?,
  )
  .decompress()
  .ok_or_else(|| RpcError::InvalidPoint(point.to_string()))
}

#[derive(Clone, Debug)]
pub struct Rpc(String);

impl Rpc {
  pub fn new(daemon: String) -> Rpc {
    Rpc(daemon)
  }

  pub async fn rpc_call<Params: Serialize + Debug, Response: DeserializeOwned + Debug>(
    &self,
    method: &str,
    params: Option<Params>,
  ) -> Result<Response, RpcError> {
    let client = reqwest::Client::new();
    let mut builder = client.post(&(self.0.clone() + "/" + method));
    if let Some(params) = params.as_ref() {
      builder = builder.json(params);
    }

    self.call_tail(method, builder).await
  }

  pub async fn bin_call<Response: DeserializeOwned + Debug>(
    &self,
    method: &str,
    params: Vec<u8>,
  ) -> Result<Response, RpcError> {
    let client = reqwest::Client::new();
    let builder = client.post(&(self.0.clone() + "/" + method)).body(params);
    self.call_tail(method, builder.header("Content-Type", "application/octet-stream")).await
  }

  async fn call_tail<Response: DeserializeOwned + Debug>(
    &self,
    method: &str,
    builder: reqwest::RequestBuilder,
  ) -> Result<Response, RpcError> {
    let res = builder.send().await.map_err(|_| RpcError::ConnectionError)?;

    Ok(if !method.ends_with(".bin") {
      serde_json::from_str(&res.text().await.map_err(|_| RpcError::ConnectionError)?)
        .map_err(|_| RpcError::InternalError("Failed to parse JSON response".to_string()))?
    } else {
      monero_epee_bin_serde::from_bytes(&res.bytes().await.map_err(|_| RpcError::ConnectionError)?)
        .map_err(|_| RpcError::InternalError("Failed to parse binary response".to_string()))?
    })
  }

  pub async fn get_protocol(&self) -> Result<Protocol, RpcError> {
    #[derive(Deserialize, Debug)]
    struct ProtocolResponse {
      major_version: usize,
    }

    #[derive(Deserialize, Debug)]
    struct LastHeaderResponse {
      block_header: ProtocolResponse,
    }

    Ok(
      match self
        .rpc_call::<_, JsonRpcResponse<LastHeaderResponse>>(
          "json_rpc",
          Some(json!({
            "method": "get_last_block_header"
          })),
        )
        .await?
        .result
        .block_header
        .major_version
      {
        13 | 14 => Protocol::v14,
        15 | 16 => Protocol::v16,
        _ => Protocol::Unsupported,
      },
    )
  }

  pub async fn get_height(&self) -> Result<usize, RpcError> {
    #[derive(Deserialize, Debug)]
    struct HeightResponse {
      height: usize,
    }
    Ok(self.rpc_call::<Option<()>, HeightResponse>("get_height", None).await?.height)
  }

  async fn get_transactions_core(
    &self,
    hashes: &[[u8; 32]],
  ) -> Result<(Vec<Result<Transaction, RpcError>>, Vec<[u8; 32]>), RpcError> {
    if hashes.is_empty() {
      return Ok((vec![], vec![]));
    }

    #[derive(Deserialize, Debug)]
    struct TransactionResponse {
      tx_hash: String,
      as_hex: String,
      pruned_as_hex: String,
    }
    #[derive(Deserialize, Debug)]
    struct TransactionsResponse {
      #[serde(default)]
      missed_tx: Vec<String>,
      txs: Vec<TransactionResponse>,
    }

    let txs: TransactionsResponse = self
      .rpc_call(
        "get_transactions",
        Some(json!({
          "txs_hashes": hashes.iter().map(|hash| hex::encode(&hash)).collect::<Vec<_>>()
        })),
      )
      .await?;

    Ok((
      txs
        .txs
        .iter()
        .map(|res| {
          let tx = Transaction::deserialize(&mut std::io::Cursor::new(
            rpc_hex(if !res.as_hex.is_empty() { &res.as_hex } else { &res.pruned_as_hex }).unwrap(),
          ))
          .map_err(|_| {
            RpcError::InvalidTransaction(hex::decode(&res.tx_hash).unwrap().try_into().unwrap())
          })?;

          // https://github.com/monero-project/monero/issues/8311
          if res.as_hex.is_empty() {
            match tx.prefix.inputs.get(0) {
              Some(Input::Gen { .. }) => (),
              _ => Err(RpcError::PrunedTransaction)?,
            }
          }

          Ok(tx)
        })
        .collect(),
      txs.missed_tx.iter().map(|hash| hex::decode(&hash).unwrap().try_into().unwrap()).collect(),
    ))
  }

  pub async fn get_transactions(&self, hashes: &[[u8; 32]]) -> Result<Vec<Transaction>, RpcError> {
    let (txs, missed) = self.get_transactions_core(hashes).await?;
    if !missed.is_empty() {
      Err(RpcError::TransactionsNotFound(missed))?;
    }
    // This will clone several KB and is accordingly inefficient
    // TODO: Optimize
    txs.iter().cloned().collect::<Result<_, _>>()
  }

  pub async fn get_transactions_possible(
    &self,
    hashes: &[[u8; 32]],
  ) -> Result<Vec<Transaction>, RpcError> {
    let (txs, _) = self.get_transactions_core(hashes).await?;
    Ok(txs.iter().cloned().filter_map(|tx| tx.ok()).collect())
  }

  pub async fn get_block(&self, height: usize) -> Result<Block, RpcError> {
    #[derive(Deserialize, Debug)]
    struct BlockResponse {
      blob: String,
    }

    let block: JsonRpcResponse<BlockResponse> = self
      .rpc_call(
        "json_rpc",
        Some(json!({
          "method": "get_block",
          "params": {
            "height": height
          }
        })),
      )
      .await?;

    Ok(
      Block::deserialize(&mut std::io::Cursor::new(rpc_hex(&block.result.blob)?))
        .expect("Monero returned a block we couldn't deserialize"),
    )
  }

  async fn get_block_transactions_core(
    &self,
    height: usize,
    possible: bool,
  ) -> Result<Vec<Transaction>, RpcError> {
    let block = self.get_block(height).await?;
    let mut res = vec![block.miner_tx];
    res.extend(if possible {
      self.get_transactions_possible(&block.txs).await?
    } else {
      self.get_transactions(&block.txs).await?
    });
    Ok(res)
  }

  pub async fn get_block_transactions(&self, height: usize) -> Result<Vec<Transaction>, RpcError> {
    self.get_block_transactions_core(height, false).await
  }

  pub async fn get_block_transactions_possible(
    &self,
    height: usize,
  ) -> Result<Vec<Transaction>, RpcError> {
    self.get_block_transactions_core(height, true).await
  }

  pub async fn get_o_indexes(&self, hash: [u8; 32]) -> Result<Vec<u64>, RpcError> {
    #[derive(Serialize, Debug)]
    struct Request {
      txid: [u8; 32],
    }

    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct OIndexes {
      o_indexes: Vec<u64>,
      status: String,
      untrusted: bool,
      credits: usize,
      top_hash: String,
    }

    let indexes: OIndexes = self
      .bin_call(
        "get_o_indexes.bin",
        monero_epee_bin_serde::to_bytes(&Request { txid: hash }).unwrap(),
      )
      .await?;

    Ok(indexes.o_indexes)
  }

  // from and to are inclusive
  pub async fn get_output_distribution(
    &self,
    from: usize,
    to: usize,
  ) -> Result<Vec<u64>, RpcError> {
    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    pub struct Distribution {
      distribution: Vec<u64>,
    }

    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct Distributions {
      distributions: Vec<Distribution>,
    }

    let mut distributions: JsonRpcResponse<Distributions> = self
      .rpc_call(
        "json_rpc",
        Some(json!({
          "method": "get_output_distribution",
          "params": {
            "binary": false,
            "amounts": [0],
            "cumulative": true,
            "from_height": from,
            "to_height": to
          }
        })),
      )
      .await?;

    Ok(distributions.result.distributions.swap_remove(0).distribution)
  }

  pub async fn get_outputs(
    &self,
    indexes: &[u64],
    height: usize,
  ) -> Result<Vec<Option<[EdwardsPoint; 2]>>, RpcError> {
    #[derive(Deserialize, Debug)]
    pub struct Out {
      key: String,
      mask: String,
      txid: String,
    }

    #[derive(Deserialize, Debug)]
    struct Outs {
      outs: Vec<Out>,
    }

    let outs: Outs = self
      .rpc_call(
        "get_outs",
        Some(json!({
          "get_txid": true,
          "outputs": indexes.iter().map(|o| json!({
            "amount": 0,
            "index": o
          })).collect::<Vec<_>>()
        })),
      )
      .await?;

    let txs = self
      .get_transactions(
        &outs
          .outs
          .iter()
          .map(|out| {
            rpc_hex(&out.txid)
              .expect("Monero returned an invalidly encoded hash")
              .try_into()
              .expect("Monero returned an invalid sized hash")
          })
          .collect::<Vec<_>>(),
      )
      .await?;
    // TODO: Support time based lock times. These shouldn't be needed, and it may be painful to
    // get the median time for the given height, yet we do need to in order to be complete
    outs
      .outs
      .iter()
      .enumerate()
      .map(|(i, out)| {
        Ok(Some([rpc_point(&out.key)?, rpc_point(&out.mask)?]).filter(|_| {
          match txs[i].prefix.timelock {
            Timelock::Block(t_height) => (t_height <= height),
            _ => false,
          }
        }))
      })
      .collect()
  }

  pub async fn get_fee(&self) -> Result<Fee, RpcError> {
    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct FeeResponse {
      fee: u64,
      quantization_mask: u64,
    }

    let res: JsonRpcResponse<FeeResponse> = self
      .rpc_call(
        "json_rpc",
        Some(json!({
          "method": "get_fee_estimate"
        })),
      )
      .await?;

    Ok(Fee { per_weight: res.result.fee, mask: res.result.quantization_mask })
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
      reason: String,
    }

    let mut buf = Vec::with_capacity(2048);
    tx.serialize(&mut buf).unwrap();
    let res: SendRawResponse = self
      .rpc_call("send_raw_transaction", Some(json!({ "tx_as_hex": hex::encode(&buf) })))
      .await?;

    if res.status != "OK" {
      Err(RpcError::InvalidTransaction(tx.hash()))?;
    }

    Ok(())
  }
}
