#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use core::{
  fmt::Debug,
  ops::{Bound, RangeBounds},
};
use std_shims::{
  alloc::{boxed::Box, format},
  vec,
  vec::Vec,
  io,
  string::{String, ToString},
};

use zeroize::Zeroize;

use async_trait::async_trait;

use curve25519_dalek::edwards::EdwardsPoint;

use serde::{Serialize, Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};

use monero_serai::{
  io::*,
  transaction::{Input, Timelock, Transaction},
  block::Block,
};
use monero_address::Address;

// Number of blocks the fee estimate will be valid for
// https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
//   src/wallet/wallet2.cpp#L121
const GRACE_BLOCKS_FOR_FEE_ESTIMATE: u64 = 10;

/// An error from the RPC.
#[derive(Clone, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum RpcError {
  /// An internal error.
  #[cfg_attr(feature = "std", error("internal error ({0})"))]
  InternalError(String),
  /// A connection error with the node.
  #[cfg_attr(feature = "std", error("connection error ({0})"))]
  ConnectionError(String),
  /// The node is invalid per the expected protocol.
  #[cfg_attr(feature = "std", error("invalid node ({0})"))]
  InvalidNode(String),
  /// Requested transactions weren't found.
  #[cfg_attr(feature = "std", error("transactions not found"))]
  TransactionsNotFound(Vec<[u8; 32]>),
  /// The transaction was pruned.
  ///
  /// Pruned transactions are not supported at this time.
  #[cfg_attr(feature = "std", error("pruned transaction"))]
  PrunedTransaction,
  /// A transaction (sent or received) was invalid.
  #[cfg_attr(feature = "std", error("invalid transaction ({0:?})"))]
  InvalidTransaction([u8; 32]),
  /// The returned fee was unusable.
  #[cfg_attr(feature = "std", error("unexpected fee response"))]
  InvalidFee,
  /// The priority intended for use wasn't usable.
  #[cfg_attr(feature = "std", error("invalid priority"))]
  InvalidPriority,
}

/// A struct containing a fee rate.
///
/// The fee rate is defined as a per-weight cost, along with a mask for rounding purposes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct FeeRate {
  /// The fee per-weight of the transaction.
  per_weight: u64,
  /// The mask to round with.
  mask: u64,
}

impl FeeRate {
  /// Construct a new fee rate.
  pub fn new(per_weight: u64, mask: u64) -> Result<FeeRate, RpcError> {
    if (per_weight == 0) || (mask == 0) {
      Err(RpcError::InvalidFee)?;
    }
    Ok(FeeRate { per_weight, mask })
  }

  /// Write the FeeRate.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn write(&self, w: &mut impl io::Write) -> io::Result<()> {
    w.write_all(&self.per_weight.to_le_bytes())?;
    w.write_all(&self.mask.to_le_bytes())
  }

  /// Serialize the FeeRate to a `Vec<u8>`.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = Vec::with_capacity(16);
    self.write(&mut res).unwrap();
    res
  }

  /// Read a FeeRate.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn read(r: &mut impl io::Read) -> io::Result<FeeRate> {
    let per_weight = read_u64(r)?;
    let mask = read_u64(r)?;
    FeeRate::new(per_weight, mask).map_err(io::Error::other)
  }

  /// Calculate the fee to use from the weight.
  ///
  /// This function may panic upon overflow.
  pub fn calculate_fee_from_weight(&self, weight: usize) -> u64 {
    let fee = self.per_weight * u64::try_from(weight).unwrap();
    let fee = fee.div_ceil(self.mask) * self.mask;
    debug_assert_eq!(weight, self.calculate_weight_from_fee(fee), "Miscalculated weight from fee");
    fee
  }

  /// Calculate the weight from the fee.
  pub fn calculate_weight_from_fee(&self, fee: u64) -> usize {
    usize::try_from(fee / self.per_weight).unwrap()
  }
}

/// The priority for the fee.
///
/// Higher-priority transactions will be included in blocks earlier.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[allow(non_camel_case_types)]
pub enum FeePriority {
  /// The `Unimportant` priority, as defined by Monero.
  Unimportant,
  /// The `Normal` priority, as defined by Monero.
  Normal,
  /// The `Elevated` priority, as defined by Monero.
  Elevated,
  /// The `Priority` priority, as defined by Monero.
  Priority,
  /// A custom priority.
  Custom {
    /// The numeric representation of the priority, as used within the RPC.
    priority: u32,
  },
}

/// https://github.com/monero-project/monero/blob/ac02af92867590ca80b2779a7bbeafa99ff94dcb/
///   src/simplewallet/simplewallet.cpp#L161
impl FeePriority {
  pub(crate) fn fee_priority(&self) -> u32 {
    match self {
      FeePriority::Unimportant => 1,
      FeePriority::Normal => 2,
      FeePriority::Elevated => 3,
      FeePriority::Priority => 4,
      FeePriority::Custom { priority, .. } => *priority,
    }
  }
}

#[derive(Debug, Deserialize)]
struct EmptyResponse {}
#[derive(Debug, Deserialize)]
struct JsonRpcResponse<T> {
  result: T,
}

#[derive(Debug, Deserialize)]
struct TransactionResponse {
  tx_hash: String,
  as_hex: String,
  pruned_as_hex: String,
}
#[derive(Debug, Deserialize)]
struct TransactionsResponse {
  #[serde(default)]
  missed_tx: Vec<String>,
  txs: Vec<TransactionResponse>,
}

/// The response to an output query.
#[derive(Debug, Deserialize)]
pub struct OutputResponse {
  /// The height of the block this output was added to the chain in.
  pub height: usize,
  /// If the output is unlocked, per the node's local view.
  pub unlocked: bool,
  /// The output's key.
  pub key: String,
  /// The output's commitment.
  pub mask: String,
  /// The transaction which created this output.
  pub txid: String,
}

fn rpc_hex(value: &str) -> Result<Vec<u8>, RpcError> {
  hex::decode(value).map_err(|_| RpcError::InvalidNode("expected hex wasn't hex".to_string()))
}

fn hash_hex(hash: &str) -> Result<[u8; 32], RpcError> {
  rpc_hex(hash)?.try_into().map_err(|_| RpcError::InvalidNode("hash wasn't 32-bytes".to_string()))
}

fn rpc_point(point: &str) -> Result<EdwardsPoint, RpcError> {
  decompress_point(
    rpc_hex(point)?
      .try_into()
      .map_err(|_| RpcError::InvalidNode(format!("invalid point: {point}")))?,
  )
  .ok_or_else(|| RpcError::InvalidNode(format!("invalid point: {point}")))
}

/// An RPC connection to a Monero daemon.
///
/// This is abstract such that users can use an HTTP library (which being their choice), a
/// Tor/i2p-based transport, or even a memory buffer an external service somehow routes.
///
/// While no implementors are directly provided, [monero-simple-request-rpc](
///   https://github.com/serai-dex/serai/tree/develop/coins/monero/rpc/simple-request
/// ) is recommended.
#[async_trait]
pub trait Rpc: Sync + Clone + Debug {
  /// Perform a POST request to the specified route with the specified body.
  ///
  /// The implementor is left to handle anything such as authentication.
  async fn post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError>;

  /// Perform a RPC call to the specified route with the provided parameters.
  ///
  /// This is NOT a JSON-RPC call. They use a route of "json_rpc" and are available via
  /// `json_rpc_call`.
  async fn rpc_call<Params: Send + Serialize + Debug, Response: DeserializeOwned + Debug>(
    &self,
    route: &str,
    params: Option<Params>,
  ) -> Result<Response, RpcError> {
    let res = self
      .post(
        route,
        if let Some(params) = params {
          serde_json::to_string(&params).unwrap().into_bytes()
        } else {
          vec![]
        },
      )
      .await?;
    let res_str = std_shims::str::from_utf8(&res)
      .map_err(|_| RpcError::InvalidNode("response wasn't utf-8".to_string()))?;
    serde_json::from_str(res_str)
      .map_err(|_| RpcError::InvalidNode(format!("response wasn't the expected json: {res_str}")))
  }

  /// Perform a JSON-RPC call with the specified method with the provided parameters.
  async fn json_rpc_call<Response: DeserializeOwned + Debug>(
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
  async fn bin_call(&self, route: &str, params: Vec<u8>) -> Result<Vec<u8>, RpcError> {
    self.post(route, params).await
  }

  /// Get the active blockchain protocol version.
  ///
  /// This is specifically the major version within the most recent block header.
  async fn get_hardfork_version(&self) -> Result<u8, RpcError> {
    #[derive(Debug, Deserialize)]
    struct HeaderResponse {
      major_version: u8,
    }

    #[derive(Debug, Deserialize)]
    struct LastHeaderResponse {
      block_header: HeaderResponse,
    }

    Ok(
      self
        .json_rpc_call::<LastHeaderResponse>("get_last_block_header", None)
        .await?
        .block_header
        .major_version,
    )
  }

  /// Get the height of the Monero blockchain.
  ///
  /// The height is defined as the amount of blocks on the blockchain. For a blockchain with only
  /// its genesis block, the height will be 1.
  async fn get_height(&self) -> Result<usize, RpcError> {
    #[derive(Debug, Deserialize)]
    struct HeightResponse {
      height: usize,
    }
    let res = self.rpc_call::<Option<()>, HeightResponse>("get_height", None).await?.height;
    if res == 0 {
      Err(RpcError::InvalidNode("node responded with 0 for the height".to_string()))?;
    }
    Ok(res)
  }

  /// Get the specified transactions.
  ///
  /// The received transactions will be hashed in order to verify the correct transactions were
  /// returned.
  async fn get_transactions(&self, hashes: &[[u8; 32]]) -> Result<Vec<Transaction>, RpcError> {
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
          match tx.prefix().inputs.first() {
            Some(Input::Gen { .. }) => (),
            _ => Err(RpcError::PrunedTransaction)?,
          }
        }

        // This does run a few keccak256 hashes, which is pointless if the node is trusted
        // In exchange, this provides resilience against invalid/malicious nodes
        if tx.hash() != hashes[i] {
          Err(RpcError::InvalidNode(
            "replied with transaction wasn't the requested transaction".to_string(),
          ))?;
        }

        Ok(tx)
      })
      .collect()
  }

  /// Get the specified transaction.
  ///
  /// The received transaction will be hashed in order to verify the correct transaction was
  /// returned.
  async fn get_transaction(&self, tx: [u8; 32]) -> Result<Transaction, RpcError> {
    self.get_transactions(&[tx]).await.map(|mut txs| txs.swap_remove(0))
  }

  /// Get the hash of a block from the node.
  ///
  /// `number` is the block's zero-indexed position on the blockchain (`0` for the genesis block,
  /// `height - 1` for the latest block).
  async fn get_block_hash(&self, number: usize) -> Result<[u8; 32], RpcError> {
    #[derive(Debug, Deserialize)]
    struct BlockHeaderResponse {
      hash: String,
    }
    #[derive(Debug, Deserialize)]
    struct BlockHeaderByHeightResponse {
      block_header: BlockHeaderResponse,
    }

    let header: BlockHeaderByHeightResponse =
      self.json_rpc_call("get_block_header_by_height", Some(json!({ "height": number }))).await?;
    hash_hex(&header.block_header.hash)
  }

  /// Get a block from the node by its hash.
  ///
  /// The received block will be hashed in order to verify the correct block was returned.
  async fn get_block(&self, hash: [u8; 32]) -> Result<Block, RpcError> {
    #[derive(Debug, Deserialize)]
    struct BlockResponse {
      blob: String,
    }

    let res: BlockResponse =
      self.json_rpc_call("get_block", Some(json!({ "hash": hex::encode(hash) }))).await?;

    let block = Block::read::<&[u8]>(&mut rpc_hex(&res.blob)?.as_ref())
      .map_err(|_| RpcError::InvalidNode("invalid block".to_string()))?;
    if block.hash() != hash {
      Err(RpcError::InvalidNode("different block than requested (hash)".to_string()))?;
    }
    Ok(block)
  }

  /// Get a block from the node by its number.
  ///
  /// `number` is the block's zero-indexed position on the blockchain (`0` for the genesis block,
  /// `height - 1` for the latest block).
  async fn get_block_by_number(&self, number: usize) -> Result<Block, RpcError> {
    #[derive(Debug, Deserialize)]
    struct BlockResponse {
      blob: String,
    }

    let res: BlockResponse =
      self.json_rpc_call("get_block", Some(json!({ "height": number }))).await?;

    let block = Block::read::<&[u8]>(&mut rpc_hex(&res.blob)?.as_ref())
      .map_err(|_| RpcError::InvalidNode("invalid block".to_string()))?;

    // Make sure this is actually the block for this number
    match block.miner_transaction.prefix().inputs.first() {
      Some(Input::Gen(actual)) => {
        if *actual == number {
          Ok(block)
        } else {
          Err(RpcError::InvalidNode("different block than requested (number)".to_string()))
        }
      }
      _ => Err(RpcError::InvalidNode(
        "block's miner_transaction didn't have an input of kind Input::Gen".to_string(),
      )),
    }
  }

  /// Get the transactions within a block.
  ///
  /// This function returns all transactions in the block, including the miner's transaction.
  ///
  /// This function does not verify the returned transactions are the ones committed to by the
  /// block's header.
  async fn get_block_transactions(&self, hash: [u8; 32]) -> Result<Vec<Transaction>, RpcError> {
    let block = self.get_block(hash).await?;
    let mut res = vec![block.miner_transaction];
    res.extend(self.get_transactions(&block.transactions).await?);
    Ok(res)
  }

  /// Get the transactions within a block.
  ///
  /// This function returns all transactions in the block, including the miner's transaction.
  ///
  /// This function does not verify the returned transactions are the ones committed to by the
  /// block's header.
  async fn get_block_transactions_by_number(
    &self,
    number: usize,
  ) -> Result<Vec<Transaction>, RpcError> {
    let block = self.get_block_by_number(number).await?;
    let mut res = vec![block.miner_transaction];
    res.extend(self.get_transactions(&block.transactions).await?);
    Ok(res)
  }

  /// Get the currently estimated fee rate from the node.
  ///
  /// This may be manipulated to unsafe levels and MUST be sanity checked.
  ///
  /// This MUST NOT be expected to be deterministic in any way.
  // TODO: Take a sanity check argument
  async fn get_fee_rate(&self, priority: FeePriority) -> Result<FeeRate, RpcError> {
    #[derive(Debug, Deserialize)]
    struct FeeResponse {
      status: String,
      fees: Option<Vec<u64>>,
      fee: u64,
      quantization_mask: u64,
    }

    let res: FeeResponse = self
      .json_rpc_call(
        "get_fee_estimate",
        Some(json!({ "grace_blocks": GRACE_BLOCKS_FOR_FEE_ESTIMATE })),
      )
      .await?;

    if res.status != "OK" {
      Err(RpcError::InvalidFee)?;
    }

    if let Some(fees) = res.fees {
      // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
      // src/wallet/wallet2.cpp#L7615-L7620
      let priority_idx = usize::try_from(if priority.fee_priority() >= 4 {
        3
      } else {
        priority.fee_priority().saturating_sub(1)
      })
      .map_err(|_| RpcError::InvalidPriority)?;

      if priority_idx >= fees.len() {
        Err(RpcError::InvalidPriority)
      } else {
        FeeRate::new(fees[priority_idx], res.quantization_mask)
      }
    } else {
      // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
      //   src/wallet/wallet2.cpp#L7569-L7584
      // https://github.com/monero-project/monero/blob/94e67bf96bbc010241f29ada6abc89f49a81759c/
      //   src/wallet/wallet2.cpp#L7660-L7661
      let priority_idx =
        usize::try_from(if priority.fee_priority() == 0 { 1 } else { priority.fee_priority() - 1 })
          .map_err(|_| RpcError::InvalidPriority)?;
      let multipliers = [1, 5, 25, 1000];
      if priority_idx >= multipliers.len() {
        // though not an RPC error, it seems sensible to treat as such
        Err(RpcError::InvalidPriority)?;
      }
      let fee_multiplier = multipliers[priority_idx];

      FeeRate::new(res.fee * fee_multiplier, res.quantization_mask)
    }
  }

  /// Publish a transaction.
  async fn publish_transaction(&self, tx: &Transaction) -> Result<(), RpcError> {
    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
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
      .rpc_call(
        "send_raw_transaction",
        Some(json!({ "tx_as_hex": hex::encode(tx.serialize()), "do_sanity_checks": false })),
      )
      .await?;

    if res.status != "OK" {
      Err(RpcError::InvalidTransaction(tx.hash()))?;
    }

    Ok(())
  }

  /// Generate blocks, with the specified address receiving the block reward.
  ///
  /// Returns the hashes of the generated blocks and the last block's number.
  async fn generate_blocks<const ADDR_BYTES: u128>(
    &self,
    address: &Address<ADDR_BYTES>,
    block_count: usize,
  ) -> Result<(Vec<[u8; 32]>, usize), RpcError> {
    #[derive(Debug, Deserialize)]
    struct BlocksResponse {
      blocks: Vec<String>,
      height: usize,
    }

    let res = self
      .json_rpc_call::<BlocksResponse>(
        "generateblocks",
        Some(json!({
          "wallet_address": address.to_string(),
          "amount_of_blocks": block_count
        })),
      )
      .await?;

    let mut blocks = Vec::with_capacity(res.blocks.len());
    for block in res.blocks {
      blocks.push(hash_hex(&block)?);
    }
    Ok((blocks, res.height))
  }

  /// Get the output indexes of the specified transaction.
  async fn get_o_indexes(&self, hash: [u8; 32]) -> Result<Vec<u64>, RpcError> {
    // Given the immaturity of Rust epee libraries, this is a homegrown one which is only validated
    // to work against this specific function

    // Header for EPEE, an 8-byte magic and a version
    const EPEE_HEADER: &[u8] = b"\x01\x11\x01\x01\x01\x01\x02\x01\x01";

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
      let mut res = None;
      let mut has_status = false;

      if read_bytes::<_, { EPEE_HEADER.len() }>(&mut indexes)? != EPEE_HEADER {
        Err(io::Error::other("invalid header"))?;
      }

      let read_object = |reader: &mut &[u8]| -> io::Result<Vec<u64>> {
        // Read the amount of fields
        let fields = read_byte(reader)? >> 2;

        for _ in 0 .. fields {
          // Read the length of the field's name
          let name_len = read_byte(reader)?;
          // Read the name of the field
          let name = read_raw_vec(read_byte, name_len.into(), reader)?;

          let type_with_array_flag = read_byte(reader)?;
          // The type of this field, without the potentially set array flag
          let kind = type_with_array_flag & (!0x80);
          let has_array_flag = type_with_array_flag != kind;

          // Read this many instances of the field
          let iters = if has_array_flag { read_epee_vi(reader)? } else { 1 };

          // Check the field type
          {
            #[allow(clippy::match_same_arms)]
            let (expected_type, expected_array_flag) = match name.as_slice() {
              b"o_indexes" => (5, true),
              b"status" => (10, false),
              b"untrusted" => (11, false),
              b"credits" => (5, false),
              b"top_hash" => (10, false),
              // On-purposely prints name as a byte vector to prevent printing arbitrary strings
              // This is a self-describing format so we don't have to error here, yet we don't
              // claim this to be a complete deserialization function
              // To ensure it works for this specific use case, it's best to ensure it's limited
              // to this specific use case (ensuring we have less variables to deal with)
              _ => Err(io::Error::other(format!("unrecognized field in get_o_indexes: {name:?}")))?,
            };
            if (expected_type != kind) || (expected_array_flag != has_array_flag) {
              let fmt_array_bool = |array_bool| if array_bool { "array" } else { "not array" };
              Err(io::Error::other(format!(
                "field {name:?} was {kind} ({}), expected {expected_type} ({})",
                fmt_array_bool(has_array_flag),
                fmt_array_bool(expected_array_flag)
              )))?;
            }
          }

          let read_field_as_bytes = match kind {
            /*
            // i64
            1 => |reader: &mut &[u8]| read_raw_vec(read_byte, 8, reader),
            // i32
            2 => |reader: &mut &[u8]| read_raw_vec(read_byte, 4, reader),
            // i16
            3 => |reader: &mut &[u8]| read_raw_vec(read_byte, 2, reader),
            // i8
            4 => |reader: &mut &[u8]| read_raw_vec(read_byte, 1, reader),
            */
            // u64
            5 => |reader: &mut &[u8]| read_raw_vec(read_byte, 8, reader),
            /*
            // u32
            6 => |reader: &mut &[u8]| read_raw_vec(read_byte, 4, reader),
            // u16
            7 => |reader: &mut &[u8]| read_raw_vec(read_byte, 2, reader),
            // u8
            8 => |reader: &mut &[u8]| read_raw_vec(read_byte, 1, reader),
            // double
            9 => |reader: &mut &[u8]| read_raw_vec(read_byte, 8, reader),
            */
            // string, or any collection of bytes
            10 => |reader: &mut &[u8]| {
              let len = read_epee_vi(reader)?;
              read_raw_vec(
                read_byte,
                len.try_into().map_err(|_| io::Error::other("u64 length exceeded usize"))?,
                reader,
              )
            },
            // bool
            11 => |reader: &mut &[u8]| read_raw_vec(read_byte, 1, reader),
            /*
            // object, errors here as it shouldn't be used on this call
            12 => {
              |_: &mut &[u8]| Err(io::Error::other("node used object in reply to get_o_indexes"))
            }
            // array, so far unused
            13 => |_: &mut &[u8]| Err(io::Error::other("node used the unused array type")),
            */
            _ => |_: &mut &[u8]| Err(io::Error::other("node used an invalid type")),
          };

          let mut bytes_res = vec![];
          for _ in 0 .. iters {
            bytes_res.push(read_field_as_bytes(reader)?);
          }

          let mut actual_res = Vec::with_capacity(bytes_res.len());
          match name.as_slice() {
            b"o_indexes" => {
              for o_index in bytes_res {
                actual_res.push(read_u64(&mut o_index.as_slice())?);
              }
              res = Some(actual_res);
            }
            b"status" => {
              if bytes_res
                .first()
                .ok_or_else(|| io::Error::other("status was a 0-length array"))?
                .as_slice() !=
                b"OK"
              {
                Err(io::Error::other("response wasn't OK"))?;
              }
              has_status = true;
            }
            b"untrusted" | b"credits" | b"top_hash" => continue,
            _ => Err(io::Error::other("unrecognized field in get_o_indexes"))?,
          }
        }

        if !has_status {
          Err(io::Error::other("response didn't contain a status"))?;
        }

        // If the Vec was empty, it would've been omitted, hence the unwrap_or
        // TODO: Test against a 0-output TX, such as the ones found in block 202612
        Ok(res.unwrap_or(vec![]))
      };

      read_object(&mut indexes)
    })()
    .map_err(|e| RpcError::InvalidNode(format!("invalid binary response: {e:?}")))
  }
}

/// A trait for any object which can be used to select RingCT decoys.
///
/// An implementation is provided for any satisfier of `Rpc`. It is not recommended to use an `Rpc`
/// object to satisfy this. This should be satisfied by a local store of the output distribution,
/// both for performance and to prevent potential attacks a remote node can perform.
#[async_trait]
pub trait DecoyRpc: Sync + Clone + Debug {
  /// Get the height the output distribution ends at.
  ///
  /// This is equivalent to the hight of the blockchain it's for. This is intended to be cheaper
  /// than fetching the entire output distribution.
  async fn get_output_distribution_end_height(&self) -> Result<usize, RpcError>;

  /// Get the RingCT (zero-amount) output distribution.
  ///
  /// `range` is in terms of block numbers. The result may be smaller than the requested range if
  /// the range starts before RingCT outputs were created on-chain.
  async fn get_output_distribution(
    &self,
    range: impl Send + RangeBounds<usize>,
  ) -> Result<Vec<u64>, RpcError>;

  /// Get the specified outputs from the RingCT (zero-amount) pool.
  async fn get_outs(&self, indexes: &[u64]) -> Result<Vec<OutputResponse>, RpcError>;

  /// Get the specified outputs from the RingCT (zero-amount) pool, but only return them if their
  /// timelock has been satisfied.
  ///
  /// The timelock being satisfied is distinct from being free of the 10-block lock applied to all
  /// Monero transactions.
  ///
  /// The node is trusted for if the output is unlocked unless `fingerprintable_canonical` is set
  /// to true. If `fingerprintable_canonical` is set to true, the node's local view isn't used, yet
  /// the transaction's timelock is checked to be unlocked at the specified `height`. This offers a
  /// canonical decoy selection, yet is fingerprintable as time-based timelocks aren't evaluated
  /// (and considered locked, preventing their selection).
  async fn get_unlocked_outputs(
    &self,
    indexes: &[u64],
    height: usize,
    fingerprintable_canonical: bool,
  ) -> Result<Vec<Option<[EdwardsPoint; 2]>>, RpcError>;
}

#[async_trait]
impl<R: Rpc> DecoyRpc for R {
  async fn get_output_distribution_end_height(&self) -> Result<usize, RpcError> {
    <Self as Rpc>::get_height(self).await
  }

  async fn get_output_distribution(
    &self,
    range: impl Send + RangeBounds<usize>,
  ) -> Result<Vec<u64>, RpcError> {
    #[derive(Default, Debug, Deserialize)]
    struct Distribution {
      distribution: Vec<u64>,
      // A blockchain with just its genesis block has a height of 1
      start_height: usize,
    }

    #[derive(Debug, Deserialize)]
    struct Distributions {
      distributions: [Distribution; 1],
      status: String,
    }

    let from = match range.start_bound() {
      Bound::Included(from) => *from,
      Bound::Excluded(from) => from
        .checked_add(1)
        .ok_or_else(|| RpcError::InternalError("range's from wasn't representable".to_string()))?,
      Bound::Unbounded => 0,
    };
    let to = match range.end_bound() {
      Bound::Included(to) => *to,
      Bound::Excluded(to) => to
        .checked_sub(1)
        .ok_or_else(|| RpcError::InternalError("range's to wasn't representable".to_string()))?,
      Bound::Unbounded => self.get_height().await? - 1,
    };
    if from > to {
      Err(RpcError::InternalError(format!(
        "malformed range: inclusive start {from}, inclusive end {to}"
      )))?;
    }

    let zero_zero_case = (from == 0) && (to == 0);
    let distributions: Distributions = self
      .json_rpc_call(
        "get_output_distribution",
        Some(json!({
          "binary": false,
          "amounts": [0],
          "cumulative": true,
          // These are actually block numbers, not heights
          "from_height": from,
          "to_height": if zero_zero_case { 1 } else { to },
        })),
      )
      .await?;

    if distributions.status != "OK" {
      Err(RpcError::ConnectionError(
        "node couldn't service this request for the output distribution".to_string(),
      ))?;
    }

    let mut distributions = distributions.distributions;
    let Distribution { start_height, mut distribution } = core::mem::take(&mut distributions[0]);
    // start_height is also actually a block number, and it should be at least `from`
    // It may be after depending on when these outputs first appeared on the blockchain
    // Unfortunately, we can't validate without a binary search to find the RingCT activation block
    // and an iterative search from there, so we solely sanity check it
    if start_height < from {
      Err(RpcError::InvalidNode(format!(
        "requested distribution from {from} and got from {start_height}"
      )))?;
    }
    // It shouldn't be after `to` though
    if start_height > to {
      Err(RpcError::InvalidNode(format!(
        "requested distribution to {to} and got from {start_height}"
      )))?;
    }

    let expected_len = if zero_zero_case { 2 } else { (to - start_height) + 1 };
    // Yet this is actually a height
    if expected_len != distribution.len() {
      Err(RpcError::InvalidNode(format!(
        "distribution length ({}) wasn't of the requested length ({})",
        distribution.len(),
        expected_len
      )))?;
    }
    // Requesting to = 0 returns the distribution for the entire chain
    // We work-around this by requesting 0, 1 (yielding two blocks), then popping the second block
    if zero_zero_case {
      distribution.pop();
    }
    Ok(distribution)
  }

  async fn get_outs(&self, indexes: &[u64]) -> Result<Vec<OutputResponse>, RpcError> {
    #[derive(Debug, Deserialize)]
    struct OutsResponse {
      status: String,
      outs: Vec<OutputResponse>,
    }

    let res: OutsResponse = self
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

    if res.status != "OK" {
      Err(RpcError::InvalidNode("bad response to get_outs".to_string()))?;
    }

    Ok(res.outs)
  }

  async fn get_unlocked_outputs(
    &self,
    indexes: &[u64],
    height: usize,
    fingerprintable_canonical: bool,
  ) -> Result<Vec<Option<[EdwardsPoint; 2]>>, RpcError> {
    let outs: Vec<OutputResponse> = self.get_outs(indexes).await?;

    // Only need to fetch txs to do canonical check on timelock
    let txs = if fingerprintable_canonical {
      self
        .get_transactions(
          &outs.iter().map(|out| hash_hex(&out.txid)).collect::<Result<Vec<_>, _>>()?,
        )
        .await?
    } else {
      vec![]
    };

    // TODO: https://github.com/serai-dex/serai/issues/104
    outs
      .iter()
      .enumerate()
      .map(|(i, out)| {
        // Allow keys to be invalid, though if they are, return None to trigger selection of a new
        // decoy
        // Only valid keys can be used in CLSAG proofs, hence the need for re-selection, yet
        // invalid keys may honestly exist on the blockchain
        // Only a recent hard fork checked output keys were valid points
        let Some(key) = decompress_point(
          rpc_hex(&out.key)?
            .try_into()
            .map_err(|_| RpcError::InvalidNode("non-32-byte point".to_string()))?,
        ) else {
          return Ok(None);
        };
        Ok(Some([key, rpc_point(&out.mask)?]).filter(|_| {
          if fingerprintable_canonical {
            // TODO: Are timelock blocks by height or number?
            // TODO: This doesn't check the default timelock has been passed
            Timelock::Block(height) >= txs[i].prefix().additional_timelock
          } else {
            out.unlocked
          }
        }))
      })
      .collect()
  }
}
