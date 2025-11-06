#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::io::Read;

use thiserror::Error;
use core_json_traits::{JsonDeserialize, JsonStructure};
use core_json_derive::JsonDeserialize;
use simple_request::{hyper, Request, TokioClient};

use borsh::BorshDeserialize;
pub use serai_abi as abi;
use abi::{primitives::network_id::ExternalNetworkId, Event};

use async_lock::RwLock;

/// An error from the RPC.
#[derive(Debug, Error)]
pub enum RpcError {
  /// An internal error occured.
  #[error("internal error: {0}")]
  InternalError(String),
  /// A failure with the connection occurred.
  #[error("failed to communicate with serai")]
  ConnectionError,
  /// The node provided an invalid response.
  #[error("node is faulty: {0}")]
  InvalidNode(String),
  /// The response contained an error.
  #[error("error in response: {0}")]
  ErrorInResponse(String),
}

/// An RPC client to a Serai node.
#[derive(Clone)]
pub struct Serai {
  url: String,
  client: TokioClient,
}

/// An RPC client to a Serai node, scoped to a specific block.
pub struct TemporalSerai<'a> {
  serai: &'a Serai,
  block: [u8; 32],
  events: RwLock<Option<Vec<Event>>>,
}
impl Clone for TemporalSerai<'_> {
  fn clone(&self) -> Self {
    Self { serai: self.serai, block: self.block, events: RwLock::new(None) }
  }
}

impl Serai {
  async fn call<ResponseValue: Default + JsonDeserialize>(
    &self,
    method: &str,
    params: &str,
  ) -> Result<ResponseValue, RpcError> {
    let request =
      format!(r#"{{ "jsonrpc": "2.0", "id": 0, "method": {method}, "params": {params} }}"#);
    let request = hyper::Request::post(&self.url)
      .header("Content-Type", "application/json")
      .body(request.as_bytes().to_vec().into())
      .map_err(|e| RpcError::InternalError(format!("{e:?}")))?;

    #[derive(Default, JsonDeserialize)]
    pub struct Error {
      message: String,
    }
    #[derive(Default, JsonDeserialize)]
    struct Response<ResponseValue: Default + JsonDeserialize> {
      result: Option<ResponseValue>,
      error: Option<Error>,
    }

    let mut response_reader = self
      .client
      .request(request)
      .await
      .map_err(|_| RpcError::ConnectionError)?
      .body()
      .await
      .map_err(|_| RpcError::ConnectionError)?;
    let mut response_vec = Vec::with_capacity(1024);
    response_reader.read_to_end(&mut response_vec).map_err(|_| {
      RpcError::InternalError("couldn't read response from `simple-request` into `Vec`".to_string())
    })?;

    // TODO: Map `std::io::Read` into `core_json::Read` with an adapter
    let response = Response::<ResponseValue>::deserialize_structure::<
      _,
      core_json_traits::ConstStack<32>,
    >(response_vec.as_slice())
    .map_err(|e| RpcError::InvalidNode(format!("{e:?}")))?;
    match response {
      Response { result: Some(result), error: None } => Ok(result),
      Response { result: None, error: Some(error) } => {
        Err(RpcError::ErrorInResponse(error.message))
      }
      Response { result: Some(_), error: Some(_) } | Response { result: None, error: None } => {
        Err(RpcError::InvalidNode(
          "node didn't exclusively provide either `result` or `error`".to_string(),
        ))
      }
    }
  }

  /// Create a new RPC client.
  pub fn new(url: String) -> Result<Self, RpcError> {
    let client = TokioClient::with_connection_pool().map_err(|_| RpcError::ConnectionError)?;
    Ok(Serai { url, client })
  }

  /// Fetch a block from the Serai blockchain.
  pub async fn block(&self, hash: [u8; 32]) -> Result<serai_abi::Block, RpcError> {
    let bin: String = self.call("serai_block", &format!("[{}]", hex::encode(hash))).await?;
    serai_abi::Block::deserialize(
      &mut hex::decode(&bin)
        .map_err(|_| RpcError::InvalidNode("node returned non-hex-encoded block".to_string()))?
        .as_slice(),
    )
    .map_err(|_| RpcError::InvalidNode("node returned invalid block".to_string()))
  }

  /// Return the P2P addresses for the validators of the specified network.
  pub async fn p2p_validators(&self, network: ExternalNetworkId) -> Result<Vec<String>, RpcError> {
    self
      .call(
        "p2p_validators",
        match network {
          ExternalNetworkId::Bitcoin => "[bitcoin]",
          ExternalNetworkId::Ethereum => "[ethereum]",
          ExternalNetworkId::Monero => "[monero]",
          _ => Err(RpcError::InternalError("unrecognized external network ID".to_string()))?,
        },
      )
      .await
  }
}
