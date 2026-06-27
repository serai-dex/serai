use core::{str::FromStr as _, fmt::Debug};
use std::{io::Read as _, collections::HashSet};
use std_shims::prelude::*;

use thiserror::Error;

use simple_request::{hyper, Request, TokioClient as Client};

use bitcoin::{
  hashes::{Hash as _, hex::FromHex},
  consensus::encode,
  Weight, Txid, Transaction, BlockHash, Block,
};

#[derive(Clone, Debug)]
pub struct Error {
  code: isize,
  #[expect(dead_code)] // We only want the `Debug` implementation for this
  message: String,
}

/// A minimal asynchronous Bitcoin RPC client.
#[derive(Clone, Debug)]
pub struct Rpc {
  client: Client,
  url: String,
}

#[derive(Clone, Debug, Error)]
pub enum RpcError {
  #[error("couldn't connect to node")]
  ConnectionError,
  #[error("request had an error: {0:?}")]
  RequestError(Error),
  #[error("node replied with invalid JSON")]
  InvalidJson,
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
    let rpc =
      Rpc { client: Client::with_connection_pool().map_err(|_| RpcError::ConnectionError)?, url };

    // Make an RPC request to verify the node is reachable and sane
    let res: String = rpc.call("help", "[]").await?;

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
    ]);
    for line in res.split('\n') {
      // This doesn't check if the arguments are as expected
      // This is due to Bitcoin supporting a large amount of optional arguments, which
      // occasionally change, with their own mechanism of text documentation, making matching off
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
    }

    Ok(rpc)
  }

  /// Perform an arbitrary RPC call.
  ///
  /// `method` will be escaped as necessary for the JSON encoding of its string value. `params`
  /// will be interpolated into the string encoding as-is and MUST be a valid JSON value.
  ///
  /// This method is NOT guaranteed by SemVer and may be removed or modified in a future release.
  /// No guarantees on the safety nor correctness of bespoke calls made with this function are
  /// guaranteed.
  pub async fn call<Response: 'static + Default + core_json_traits::JsonDeserialize>(
    &self,
    method: &str,
    params: &str,
  ) -> Result<Response, RpcError> {
    let mut request = Request::from(
      hyper::Request::post(&self.url)
        .header("Content-Type", "application/json")
        .body(
          format!(
            r#"{{ "method": {}, "params": {params} }}"#,
            core_json_traits::JsonSerialize::serialize(method).collect::<String>()
          )
          .as_bytes()
          .to_vec()
          .into(),
        )
        .map_err(|_| RpcError::ConnectionError)?,
    );
    request.with_basic_auth();
    const HEX_ENCODED_BLOCK_LEN: u64 = 2 * Weight::MAX_BLOCK.to_wu();
    // Limit responses to the size of a block, plus an allowance for the structure of the encoding,
    // doubled to ensure this is sufficient
    request.set_response_size_limit(Some(
      2 * (usize::from(u16::MAX) + usize::try_from(HEX_ENCODED_BLOCK_LEN).unwrap()),
    ));
    let mut res = self
      .client
      .request(request)
      .await
      .map_err(|_| RpcError::ConnectionError)?
      .body()
      .await
      .map_err(|_| RpcError::ConnectionError)?;

    #[derive(Default, core_json_derive::JsonDeserialize)]
    struct InternalError {
      code: Option<i64>,
      message: Option<String>,
    }

    #[derive(core_json_derive::JsonDeserialize)]
    struct RpcResponse<T: core_json_traits::JsonDeserialize> {
      result: Option<T>,
      error: Option<InternalError>,
    }
    impl<T: core_json_traits::JsonDeserialize> Default for RpcResponse<T> {
      fn default() -> Self {
        Self { result: None, error: None }
      }
    }

    // TODO: `core_json::ReadAdapter`
    let mut res_vec = vec![];
    res.read_to_end(&mut res_vec).map_err(|_| RpcError::ConnectionError)?;
    let res = <RpcResponse<Response> as core_json_traits::JsonStructure>::deserialize_structure::<
      _,
      core_json_traits::ConstStack<32>,
    >(res_vec.as_slice())
    .map_err(|_| RpcError::InvalidJson)?;

    match res {
      RpcResponse { result: Some(result), error: None } => Ok(result),
      RpcResponse { result: None, error: Some(error) } => {
        let code =
          error.code.ok_or_else(|| RpcError::InvalidResponse("error was missing `code`"))?;
        let code = isize::try_from(code)
          .map_err(|_| RpcError::InvalidResponse("error code exceeded isize::MAX"))?;
        let message =
          error.message.ok_or_else(|| RpcError::InvalidResponse("error was missing `message`"))?;
        Err(RpcError::RequestError(Error { code, message }))
      }
      // `invalidateblock` yields this edge case
      // TODO: https://github.com/core-json/core-json/issues/18
      RpcResponse { result: None, error: None } => {
        if core::any::TypeId::of::<Response>() == core::any::TypeId::of::<()>() {
          Ok(Default::default())
        } else {
          Err(RpcError::InvalidResponse("response lacked both a result and an error"))
        }
      }
      _ => Err(RpcError::InvalidResponse("response contained both a result and an error")),
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
    usize::try_from(self.call::<u64>("getblockcount", "[]").await?)
      .map_err(|_| RpcError::InvalidResponse("latest block number exceeded usize::MAX"))
  }

  /// Get the hash of a block by the block's number.
  pub async fn get_block_hash(&self, number: usize) -> Result<[u8; 32], RpcError> {
    let hash =
      BlockHash::from_str(&self.call::<String>("getblockhash", &format!("[{number}]")).await?)
        .map_err(|_| RpcError::InvalidResponse("block hash was not valid hex"))?
        .as_raw_hash()
        .to_byte_array();
    Ok(hash)
  }

  /// Get a block's number by its hash.
  pub async fn get_block_number(&self, hash: &[u8; 32]) -> Result<usize, RpcError> {
    #[derive(Default, core_json_derive::JsonDeserialize)]
    struct Number {
      height: Option<u64>,
    }
    usize::try_from(
      self
        .call::<Number>("getblockheader", &format!(r#"["{}"]"#, encode::serialize_hex(hash)))
        .await?
        .height
        .ok_or_else(|| {
          RpcError::InvalidResponse("`getblockheader` did not include `height` field")
        })?,
    )
    .map_err(|_| RpcError::InvalidResponse("block number exceeded usize::MAX"))
  }

  /// Get a block by its hash.
  pub async fn get_block(&self, hash: &[u8; 32]) -> Result<Block, RpcError> {
    // bitcoin hex-encodes hashes in reverse order
    let mut hex = *hash;
    hex.reverse();
    let hex = encode::serialize_hex(&hex);

    let hex = self.call::<String>("getblock", &format!(r#"["{hex}", 0]"#)).await?;
    let bytes: Vec<u8> = FromHex::from_hex(&hex)
      .map_err(|_| RpcError::InvalidResponse("node didn't use hex to encode the block"))?;
    let block: Block = encode::deserialize(&bytes)
      .map_err(|_| RpcError::InvalidResponse("node sent an improperly serialized block"))?;

    if hash != block.block_hash().as_raw_hash().as_byte_array() {
      Err(RpcError::InvalidResponse("node replied with a different block"))?;
    }

    Ok(block)
  }

  /// Publish a transaction.
  pub async fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, RpcError> {
    let txid = match self
      .call::<String>("sendrawtransaction", &format!(r#"["{}"]"#, encode::serialize_hex(tx)))
      .await
    {
      Ok(txid) => {
        Txid::from_str(&txid).map_err(|_| RpcError::InvalidResponse("TXID was not valid hex"))?
      }
      Err(e) => {
        // A const from Bitcoin's bitcoin/src/rpc/protocol.h
        const RPC_VERIFY_ALREADY_IN_CHAIN: isize = -27;
        // If this was already successfully published, consider this having succeeded
        if let RpcError::RequestError(Error { code, .. }) = e {
          if code == RPC_VERIFY_ALREADY_IN_CHAIN {
            return Ok(tx.compute_txid());
          }
        }
        Err(e)?
      }
    };
    if txid != tx.compute_txid() {
      Err(RpcError::InvalidResponse("returned TX ID inequals calculated TX ID"))?;
    }
    Ok(txid)
  }
}
