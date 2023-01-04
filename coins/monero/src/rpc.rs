use std::fmt::Debug;

use thiserror::Error;

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

use digest_auth::AuthContext;
use reqwest::{Client, RequestBuilder};

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

#[derive(Deserialize, Debug)]
struct TransactionResponse {
  tx_hash: String,
  block_height: Option<usize>,
  as_hex: String,
  pruned_as_hex: String,
}
#[derive(Deserialize, Debug)]
struct TransactionsResponse {
  #[serde(default)]
  missed_tx: Vec<String>,
  txs: Vec<TransactionResponse>,
}

#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum RpcError {
  #[error("internal error ({0})")]
  InternalError(&'static str),
  #[error("connection error")]
  ConnectionError,
  #[error("invalid node")]
  InvalidNode,
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
  hex::decode(value).map_err(|_| RpcError::InvalidNode)
}

fn hash_hex(hash: &str) -> Result<[u8; 32], RpcError> {
  rpc_hex(hash)?.try_into().map_err(|_| RpcError::InvalidNode)
}

fn rpc_point(point: &str) -> Result<EdwardsPoint, RpcError> {
  CompressedEdwardsY(
    rpc_hex(point)?.try_into().map_err(|_| RpcError::InvalidPoint(point.to_string()))?,
  )
  .decompress()
  .ok_or_else(|| RpcError::InvalidPoint(point.to_string()))
}

#[derive(Clone, Debug)]
pub struct Rpc {
  client: Client,
  userpass: Option<(String, String)>,
  url: String,
}

impl Rpc {
  /// Create a new RPC connection.
  /// A daemon requiring authentication can be used via including the username and password in the
  /// URL.
  pub fn new(mut url: String) -> Result<Rpc, RpcError> {
    // Parse out the username and password
    let userpass = if url.contains('@') {
      let url_clone = url.clone();
      let split_url = url_clone.split('@').collect::<Vec<_>>();
      if split_url.len() != 2 {
        Err(RpcError::InvalidNode)?;
      }
      let mut userpass = split_url[0];
      url = split_url[1].to_string();

      // If there was additionally a protocol string, restore that to the daemon URL
      if userpass.contains("://") {
        let split_userpass = userpass.split("://").collect::<Vec<_>>();
        if split_userpass.len() != 2 {
          Err(RpcError::InvalidNode)?;
        }
        url = split_userpass[0].to_string() + "://" + &url;
        userpass = split_userpass[1];
      }

      let split_userpass = userpass.split(':').collect::<Vec<_>>();
      if split_userpass.len() != 2 {
        Err(RpcError::InvalidNode)?;
      }
      Some((split_userpass[0].to_string(), split_userpass[1].to_string()))
    } else {
      None
    };

    Ok(Rpc { client: Client::new(), userpass, url })
  }

  /// Perform a RPC call to the specified method with the provided parameters.
  /// This is NOT a JSON-RPC call, which use a method of "json_rpc" and are available via
  /// `json_rpc_call`.
  pub async fn rpc_call<Params: Serialize + Debug, Response: DeserializeOwned + Debug>(
    &self,
    method: &str,
    params: Option<Params>,
  ) -> Result<Response, RpcError> {
    let mut builder = self.client.post(self.url.clone() + "/" + method);
    if let Some(params) = params.as_ref() {
      builder = builder.json(params);
    }

    self.call_tail(method, builder).await
  }

  /// Perform a JSON-RPC call to the specified method with the provided parameters
  pub async fn json_rpc_call<Response: DeserializeOwned + Debug>(
    &self,
    method: &str,
    params: Option<Value>,
  ) -> Result<Response, RpcError> {
    let mut req = json!({ "method": method });
    if let Some(params) = params {
      req.as_object_mut().unwrap().insert("params".into(), params);
    }
    Ok(self.rpc_call::<_, JsonRpcResponse<Response>>("json_rpc", Some(req)).await?.result)
  }

  /// Perform a binary call to the specified method with the provided parameters.
  pub async fn bin_call<Response: DeserializeOwned + Debug>(
    &self,
    method: &str,
    params: Vec<u8>,
  ) -> Result<Response, RpcError> {
    let builder = self.client.post(self.url.clone() + "/" + method).body(params.clone());
    self.call_tail(method, builder.header("Content-Type", "application/octet-stream")).await
  }

  async fn call_tail<Response: DeserializeOwned + Debug>(
    &self,
    method: &str,
    mut builder: RequestBuilder,
  ) -> Result<Response, RpcError> {
    if let Some((user, pass)) = &self.userpass {
      let req = self.client.post(&self.url).send().await.map_err(|_| RpcError::InvalidNode)?;
      // Only provide authentication if this daemon actually expects it
      if let Some(header) = req.headers().get("www-authenticate") {
        builder = builder.header(
          "Authorization",
          digest_auth::parse(header.to_str().map_err(|_| RpcError::InvalidNode)?)
            .map_err(|_| RpcError::InvalidNode)?
            .respond(&AuthContext::new_post::<_, _, _, &[u8]>(
              user,
              pass,
              "/".to_string() + method,
              None,
            ))
            .map_err(|_| RpcError::InvalidNode)?
            .to_header_string(),
        );
      }
    }

    let res = builder.send().await.map_err(|_| RpcError::ConnectionError)?;

    Ok(if !method.ends_with(".bin") {
      serde_json::from_str(&res.text().await.map_err(|_| RpcError::ConnectionError)?)
        .map_err(|_| RpcError::InternalError("Failed to parse JSON response"))?
    } else {
      monero_epee_bin_serde::from_bytes(&res.bytes().await.map_err(|_| RpcError::ConnectionError)?)
        .map_err(|_| RpcError::InternalError("Failed to parse binary response"))?
    })
  }

  /// Get the active blockchain protocol version.
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
        .json_rpc_call::<LastHeaderResponse>("get_last_block_header", None)
        .await?
        .block_header
        .major_version
      {
        13 | 14 => Protocol::v14,
        15 | 16 => Protocol::v16,
        version => Protocol::Unsupported(version),
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

  pub async fn get_transactions(&self, hashes: &[[u8; 32]]) -> Result<Vec<Transaction>, RpcError> {
    if hashes.is_empty() {
      return Ok(vec![]);
    }

    let txs: TransactionsResponse = self
      .rpc_call(
        "get_transactions",
        Some(json!({
          "txs_hashes": hashes.iter().map(hex::encode).collect::<Vec<_>>()
        })),
      )
      .await?;

    if !txs.missed_tx.is_empty() {
      Err(RpcError::TransactionsNotFound(
        txs.missed_tx.iter().map(|hash| hash_hex(hash)).collect::<Result<_, _>>()?,
      ))?;
    }

    txs
      .txs
      .iter()
      .map(|res| {
        let tx = Transaction::deserialize(&mut std::io::Cursor::new(rpc_hex(
          if !res.as_hex.is_empty() { &res.as_hex } else { &res.pruned_as_hex },
        )?))
        .map_err(|_| match hash_hex(&res.tx_hash) {
          Ok(hash) => RpcError::InvalidTransaction(hash),
          Err(err) => err,
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
      .collect()
  }

  pub async fn get_transaction(&self, tx: [u8; 32]) -> Result<Transaction, RpcError> {
    self.get_transactions(&[tx]).await.map(|mut txs| txs.swap_remove(0))
  }

  pub async fn get_transaction_block_number(&self, tx: &[u8]) -> Result<Option<usize>, RpcError> {
    let txs: TransactionsResponse =
      self.rpc_call("get_transactions", Some(json!({ "txs_hashes": [hex::encode(tx)] }))).await?;

    if !txs.missed_tx.is_empty() {
      Err(RpcError::TransactionsNotFound(
        txs.missed_tx.iter().map(|hash| hash_hex(hash)).collect::<Result<_, _>>()?,
      ))?;
    }

    Ok(txs.txs[0].block_height)
  }

  pub async fn get_block(&self, height: usize) -> Result<Block, RpcError> {
    #[derive(Deserialize, Debug)]
    struct BlockResponse {
      blob: String,
    }

    let block: BlockResponse =
      self.json_rpc_call("get_block", Some(json!({ "height": height }))).await?;
    Ok(
      Block::deserialize(&mut std::io::Cursor::new(rpc_hex(&block.blob)?))
        .expect("Monero returned a block we couldn't deserialize"),
    )
  }

  pub async fn get_block_transactions(&self, height: usize) -> Result<Vec<Transaction>, RpcError> {
    let block = self.get_block(height).await?;
    let mut res = vec![block.miner_tx];
    res.extend(self.get_transactions(&block.txs).await?);
    Ok(res)
  }

  /// Get the output indexes of the specified transaction.
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

  /// Get the output distribution, from the specified height to the specified height (both
  /// inclusive).
  pub async fn get_output_distribution(
    &self,
    from: usize,
    to: usize,
  ) -> Result<Vec<u64>, RpcError> {
    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct Distribution {
      distribution: Vec<u64>,
    }

    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct Distributions {
      distributions: Vec<Distribution>,
    }

    let mut distributions: Distributions = self
      .json_rpc_call(
        "get_output_distribution",
        Some(json!({
          "binary": false,
          "amounts": [0],
          "cumulative": true,
          "from_height": from,
          "to_height": to,
        })),
      )
      .await?;

    Ok(distributions.distributions.swap_remove(0).distribution)
  }

  /// Get the specified outputs from the RingCT (zero-amount) pool, but only return them if they're
  /// unlocked.
  pub async fn get_unlocked_outputs(
    &self,
    indexes: &[u64],
    height: usize,
  ) -> Result<Vec<Option<[EdwardsPoint; 2]>>, RpcError> {
    #[derive(Deserialize, Debug)]
    struct Out {
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

    // TODO: https://github.com/serai-dex/serai/issues/104
    outs
      .outs
      .iter()
      .enumerate()
      .map(|(i, out)| {
        Ok(Some([rpc_point(&out.key)?, rpc_point(&out.mask)?]).filter(|_| {
          match txs[i].prefix.timelock {
            Timelock::Block(t_height) => t_height <= height,
            _ => false,
          }
        }))
      })
      .collect()
  }

  /// Get the currently estimated fee from the node. This may be manipulated to unsafe levels and
  /// MUST be sanity checked.
  // TODO: Take a sanity check argument
  pub async fn get_fee(&self) -> Result<Fee, RpcError> {
    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct FeeResponse {
      fee: u64,
      quantization_mask: u64,
    }

    let res: FeeResponse = self.json_rpc_call("get_fee_estimate", None).await?;
    Ok(Fee { per_weight: res.fee, mask: res.quantization_mask })
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

  pub async fn generate_blocks(&self, address: &str, block_count: usize) -> Result<(), RpcError> {
    self
      .rpc_call::<_, EmptyResponse>(
        "json_rpc",
        Some(json!({
          "method": "generateblocks",
          "params": {
            "wallet_address": address,
            "amount_of_blocks": block_count
          },
        })),
      )
      .await?;

    Ok(())
  }
}
