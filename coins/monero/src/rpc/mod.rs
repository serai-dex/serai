use core::fmt::Debug;
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
use std_shims::{
  vec::Vec,
  io,
  string::{String, ToString},
};

use async_trait::async_trait;

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

use crate::{
  Protocol,
  serialize::*,
  transaction::{Input, Timelock, Transaction},
  block::Block,
  wallet::Fee,
};

#[cfg(feature = "http_rpc")]
mod http;
#[cfg(feature = "http_rpc")]
pub use http::*;

#[derive(Deserialize, Debug)]
pub struct EmptyResponse;
#[derive(Deserialize, Debug)]
pub struct JsonRpcResponse<T> {
  result: T,
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

#[allow(clippy::std_instead_of_core)]
mod rpc_error {
  use std_shims::{vec::Vec, string::String};
  #[derive(Clone, PartialEq, Eq, Debug)]
  #[cfg_attr(feature = "std", derive(thiserror::Error))]
  pub enum RpcError {
    #[cfg_attr(feature = "std", error("internal error ({0})"))]
    InternalError(&'static str),
    #[cfg_attr(feature = "std", error("connection error"))]
    ConnectionError,
    #[cfg_attr(feature = "std", error("invalid node"))]
    InvalidNode,
    #[cfg_attr(feature = "std", error("unsupported protocol version ({0})"))]
    UnsupportedProtocol(usize),
    #[cfg_attr(feature = "std", error("transactions not found"))]
    TransactionsNotFound(Vec<[u8; 32]>),
    #[cfg_attr(feature = "std", error("invalid point ({0})"))]
    InvalidPoint(String),
    #[cfg_attr(feature = "std", error("pruned transaction"))]
    PrunedTransaction,
    #[cfg_attr(feature = "std", error("invalid transaction ({0:?})"))]
    InvalidTransaction([u8; 32]),
  }
}
pub use rpc_error::RpcError;

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

// Read an EPEE VarInt, distinct from the VarInts used throughout the rest of the protocol
fn read_epee_vi<R: io::Read>(reader: &mut R) -> io::Result<u64> {
  let vi_start = read_byte(reader)?;
  let len = match vi_start & 0b11 {
    0 => 1,
    1 => 2,
    2 => 4,
    3 => 8,
    _ => unreachable!(),
  };
  let mut vi = u64::from(vi_start >> 2);
  for i in 1 .. len {
    vi |= u64::from(read_byte(reader)?) << (((i - 1) * 8) + 6);
  }
  Ok(vi)
}

#[async_trait]
pub trait RpcConnection: Clone + Debug {
  /// Perform a POST request to the specified route with the specified body.
  ///
  /// The implementor is left to handle anything such as authentication.
  async fn post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError>;
}

// TODO: Make this provided methods for RpcConnection?
#[derive(Clone, Debug)]
pub struct Rpc<R: RpcConnection>(R);
impl<R: RpcConnection> Rpc<R> {
  /// Perform a RPC call to the specified route with the provided parameters.
  ///
  /// This is NOT a JSON-RPC call. They use a route of "json_rpc" and are available via
  /// `json_rpc_call`.
  pub async fn rpc_call<Params: Serialize + Debug, Response: DeserializeOwned + Debug>(
    &self,
    route: &str,
    params: Option<Params>,
  ) -> Result<Response, RpcError> {
    serde_json::from_str(
      std_shims::str::from_utf8(
        &self
          .0
          .post(
            route,
            if let Some(params) = params {
              serde_json::to_string(&params).unwrap().into_bytes()
            } else {
              vec![]
            },
          )
          .await?,
      )
      .map_err(|_| RpcError::InvalidNode)?,
    )
    .map_err(|_| RpcError::InvalidNode)
  }

  /// Perform a JSON-RPC call with the specified method with the provided parameters
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

  /// Perform a binary call to the specified route with the provided parameters.
  pub async fn bin_call(&self, route: &str, params: Vec<u8>) -> Result<Vec<u8>, RpcError> {
    self.0.post(route, params).await
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
        protocol => Err(RpcError::UnsupportedProtocol(protocol))?,
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

    let mut hashes_hex = hashes.iter().map(hex::encode).collect::<Vec<_>>();
    let mut all_txs = Vec::with_capacity(hashes.len());
    while !hashes_hex.is_empty() {
      // Monero errors if more than 100 is requested unless using a non-restricted RPC
      const TXS_PER_REQUEST: usize = 100;
      let this_count = TXS_PER_REQUEST.min(hashes_hex.len());

      let txs: TransactionsResponse = self
        .rpc_call(
          "get_transactions",
          Some(json!({
            "txs_hashes": hashes_hex.drain(.. this_count).collect::<Vec<_>>(),
          })),
        )
        .await?;

      if !txs.missed_tx.is_empty() {
        Err(RpcError::TransactionsNotFound(
          txs.missed_tx.iter().map(|hash| hash_hex(hash)).collect::<Result<_, _>>()?,
        ))?;
      }

      all_txs.extend(txs.txs);
    }

    all_txs
      .iter()
      .enumerate()
      .map(|(i, res)| {
        let tx = Transaction::read::<&[u8]>(
          &mut rpc_hex(if !res.as_hex.is_empty() { &res.as_hex } else { &res.pruned_as_hex })?
            .as_ref(),
        )
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

        // This does run a few keccak256 hashes, which is pointless if the node is trusted
        // In exchange, this provides resilience against invalid/malicious nodes
        if tx.hash() != hashes[i] {
          Err(RpcError::InvalidNode)?;
        }

        Ok(tx)
      })
      .collect()
  }

  pub async fn get_transaction(&self, tx: [u8; 32]) -> Result<Transaction, RpcError> {
    self.get_transactions(&[tx]).await.map(|mut txs| txs.swap_remove(0))
  }

  /// Get the hash of a block from the node by the block's numbers.
  /// This function does not verify the returned block hash is actually for the number in question.
  pub async fn get_block_hash(&self, number: usize) -> Result<[u8; 32], RpcError> {
    #[derive(Deserialize, Debug)]
    struct BlockHeaderResponse {
      hash: String,
    }
    #[derive(Deserialize, Debug)]
    struct BlockHeaderByHeightResponse {
      block_header: BlockHeaderResponse,
    }

    let header: BlockHeaderByHeightResponse =
      self.json_rpc_call("get_block_header_by_height", Some(json!({ "height": number }))).await?;
    rpc_hex(&header.block_header.hash)?.try_into().map_err(|_| RpcError::InvalidNode)
  }

  /// Get a block from the node by its hash.
  /// This function does not verify the returned block actually has the hash in question.
  pub async fn get_block(&self, hash: [u8; 32]) -> Result<Block, RpcError> {
    #[derive(Deserialize, Debug)]
    struct BlockResponse {
      blob: String,
    }

    let res: BlockResponse =
      self.json_rpc_call("get_block", Some(json!({ "hash": hex::encode(hash) }))).await?;

    let block =
      Block::read::<&[u8]>(&mut rpc_hex(&res.blob)?.as_ref()).map_err(|_| RpcError::InvalidNode)?;
    if block.hash() != hash {
      Err(RpcError::InvalidNode)?;
    }
    Ok(block)
  }

  pub async fn get_block_by_number(&self, number: usize) -> Result<Block, RpcError> {
    match self.get_block(self.get_block_hash(number).await?).await {
      Ok(block) => {
        // Make sure this is actually the block for this number
        match block.miner_tx.prefix.inputs.get(0) {
          Some(Input::Gen(actual)) => {
            if usize::try_from(*actual).unwrap() == number {
              Ok(block)
            } else {
              Err(RpcError::InvalidNode)
            }
          }
          Some(Input::ToKey { .. }) | None => Err(RpcError::InvalidNode),
        }
      }
      e => e,
    }
  }

  pub async fn get_block_transactions(&self, hash: [u8; 32]) -> Result<Vec<Transaction>, RpcError> {
    let block = self.get_block(hash).await?;
    let mut res = vec![block.miner_tx];
    res.extend(self.get_transactions(&block.txs).await?);
    Ok(res)
  }

  pub async fn get_block_transactions_by_number(
    &self,
    number: usize,
  ) -> Result<Vec<Transaction>, RpcError> {
    self.get_block_transactions(self.get_block_hash(number).await?).await
  }

  /// Get the output indexes of the specified transaction.
  pub async fn get_o_indexes(&self, hash: [u8; 32]) -> Result<Vec<u64>, RpcError> {
    /*
    TODO: Use these when a suitable epee serde lib exists

    #[derive(Serialize, Debug)]
    struct Request {
      txid: [u8; 32],
    }

    #[allow(dead_code)]
    #[derive(Deserialize, Debug)]
    struct OIndexes {
      o_indexes: Vec<u64>,
    }
    */

    // Given the immaturity of Rust epee libraries, this is a homegrown one which is only validated
    // to work against this specific function

    // Header for EPEE, an 8-byte magic and a version
    const EPEE_HEADER: &[u8] = b"\x01\x11\x01\x01\x01\x01\x02\x01\x01";

    let mut request = EPEE_HEADER.to_vec();
    // Number of fields (shifted over 2 bits as the 2 LSBs are reserved for metadata)
    request.push(1 << 2);
    // Length of field name
    request.push(4);
    // Field name
    request.extend(b"txid");
    // Type of field
    request.push(10);
    // Length of string, since this byte array is technically a string
    request.push(32 << 2);
    // The "string"
    request.extend(hash);

    let indexes_buf = self.bin_call("get_o_indexes.bin", request).await?;
    let mut indexes: &[u8] = indexes_buf.as_ref();

    (|| {
      if read_bytes::<_, { EPEE_HEADER.len() }>(&mut indexes)? != EPEE_HEADER {
        Err(io::Error::new(io::ErrorKind::Other, "invalid header"))?;
      }

      let read_object = |reader: &mut &[u8]| {
        let fields = read_byte(reader)? >> 2;

        for _ in 0 .. fields {
          let name_len = read_byte(reader)?;
          let name = read_raw_vec(read_byte, name_len.into(), reader)?;

          let type_with_array_flag = read_byte(reader)?;
          let kind = type_with_array_flag & (!0x80);

          let iters = if type_with_array_flag != kind { read_epee_vi(reader)? } else { 1 };

          if (&name == b"o_indexes") && (kind != 5) {
            Err(io::Error::new(io::ErrorKind::Other, "o_indexes weren't u64s"))?;
          }

          let f = match kind {
            // i64
            1 => |reader: &mut &[u8]| read_raw_vec(read_byte, 8, reader),
            // i32
            2 => |reader: &mut &[u8]| read_raw_vec(read_byte, 4, reader),
            // i16
            3 => |reader: &mut &[u8]| read_raw_vec(read_byte, 2, reader),
            // i8
            4 => |reader: &mut &[u8]| read_raw_vec(read_byte, 1, reader),
            // u64
            5 => |reader: &mut &[u8]| read_raw_vec(read_byte, 8, reader),
            // u32
            6 => |reader: &mut &[u8]| read_raw_vec(read_byte, 4, reader),
            // u16
            7 => |reader: &mut &[u8]| read_raw_vec(read_byte, 2, reader),
            // u8
            8 => |reader: &mut &[u8]| read_raw_vec(read_byte, 1, reader),
            // double
            9 => |reader: &mut &[u8]| read_raw_vec(read_byte, 8, reader),
            // string, or any collection of bytes
            10 => |reader: &mut &[u8]| {
              let len = read_epee_vi(reader)?;
              read_raw_vec(
                read_byte,
                len
                  .try_into()
                  .map_err(|_| io::Error::new(io::ErrorKind::Other, "u64 length exceeded usize"))?,
                reader,
              )
            },
            // bool
            11 => |reader: &mut &[u8]| read_raw_vec(read_byte, 1, reader),
            // object, errors here as it shouldn't be used on this call
            12 => |_: &mut &[u8]| {
              Err(io::Error::new(
                io::ErrorKind::Other,
                "node used object in reply to get_o_indexes",
              ))
            },
            // array, so far unused
            13 => |_: &mut &[u8]| {
              Err(io::Error::new(io::ErrorKind::Other, "node used the unused array type"))
            },
            _ => {
              |_: &mut &[u8]| Err(io::Error::new(io::ErrorKind::Other, "node used an invalid type"))
            }
          };

          let mut res = vec![];
          for _ in 0 .. iters {
            res.push(f(reader)?);
          }

          let mut actual_res = Vec::with_capacity(res.len());
          if &name == b"o_indexes" {
            for o_index in res {
              actual_res.push(u64::from_le_bytes(o_index.try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "node didn't provide 8 bytes for a u64")
              })?));
            }
            return Ok(actual_res);
          }
        }

        // Didn't return a response with o_indexes
        // TODO: Check if this didn't have o_indexes because it's an error response
        Err(io::Error::new(io::ErrorKind::Other, "response didn't contain o_indexes"))
      };

      read_object(&mut indexes)
    })()
    .map_err(|_| RpcError::InvalidNode)
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

  /// Get the specified outputs from the RingCT (zero-amount) pool, but only return them if their
  /// timelock has been satisfied. This is distinct from being free of the 10-block lock applied to
  /// all Monero transactions.
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
          .map(|out| rpc_hex(&out.txid)?.try_into().map_err(|_| RpcError::InvalidNode))
          .collect::<Result<Vec<_>, _>>()?,
      )
      .await?;

    // TODO: https://github.com/serai-dex/serai/issues/104
    outs
      .outs
      .iter()
      .enumerate()
      .map(|(i, out)| {
        Ok(
          Some([rpc_point(&out.key)?, rpc_point(&out.mask)?])
            .filter(|_| Timelock::Block(height) >= txs[i].prefix.timelock),
        )
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

    let res: SendRawResponse = self
      .rpc_call("send_raw_transaction", Some(json!({ "tx_as_hex": hex::encode(tx.serialize()) })))
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
