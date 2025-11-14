#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{ops::Deref, convert::AsRef, future::Future};
use std::{sync::Arc, io::Read};

use thiserror::Error;
use core_json_traits::{JsonDeserialize, JsonStructure};
use core_json_derive::JsonDeserialize;
use simple_request::{hyper, Request, TokioClient};

use borsh::BorshDeserialize;
pub use serai_abi as abi;
use abi::{
  primitives::{BlockHash, network_id::ExternalNetworkId},
  Block, Event,
};

use async_lock::RwLock;

/// RPC client functionality for the validator sets module.
pub mod validator_sets;
use validator_sets::*;

/// An error from the RPC.
#[derive(Debug, Error)]
pub enum RpcError {
  /// An internal error occured.
  #[error("internal error: {0}")]
  InternalError(String),
  /// A failure with the connection occurred.
  #[error("failed to communicate with serai")]
  ConnectionError(simple_request::Error),
  /// The node provided an invalid response.
  #[error("node is faulty: {0}")]
  InvalidNode(String),
  /// The response contained an error.
  #[error("error in response: {0}")]
  ErrorInResponse(String),
  /// The requested block wasn't finalized.
  #[error("the requested block wasn't finalized")]
  NotFinalized,
}

/// An RPC client to a Serai node.
#[derive(Clone)]
pub struct Serai {
  url: String,
  client: TokioClient,
}

/// An RPC client to a Serai node, scoped to a specific block.
///
/// Upon any request being made for the events emitted by this block, the entire list of events
/// from this block will be cached within this. This allows future calls for events to be done
/// cheaply.
#[derive(Clone)]
pub struct TemporalSerai<'a> {
  serai: &'a Serai,
  block: BlockHash,
  events: Arc<RwLock<Option<Vec<Event>>>>,
}

impl Serai {
  async fn call<ResponseValue: Default + JsonDeserialize>(
    &self,
    method: &str,
    params: &str,
  ) -> Result<ResponseValue, RpcError> {
    let request =
      format!(r#"{{ "jsonrpc": "2.0", "id": 0, "method": "{method}", "params": {params} }}"#);
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
      .map_err(RpcError::ConnectionError)?
      .body()
      .await
      .map_err(RpcError::ConnectionError)?;
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
      // TODO: https://github.com/core-json/core-json/issues/18
      Response { result: None, error: None } => Ok(Default::default()),
      Response { result: Some(_), error: Some(_) } => {
        Err(RpcError::InvalidNode("node didn't provided both `result` and `error`".to_string()))
      }
    }
  }

  /// Create a new RPC client.
  pub fn new(url: String) -> Result<Self, RpcError> {
    let client = TokioClient::with_connection_pool().map_err(RpcError::ConnectionError)?;
    Ok(Serai { url, client })
  }

  /// Fetch the latest finalized block number.
  pub async fn latest_finalized_block_number(&self) -> Result<u64, RpcError> {
    self.call("blockchain/latest_finalized_block_number", "[]").await
  }

  /// Fetch if a block is finalized.
  pub async fn finalized(&self, block: BlockHash) -> Result<bool, RpcError> {
    self.call("blockchain/is_finalized", &format!(r#"{{ "block": "{block}" }}"#)).await
  }

  async fn block_internal(
    block: impl Future<Output = Result<String, RpcError>>,
  ) -> Result<Block, RpcError> {
    let bin = block.await?;
    Block::deserialize(
      &mut hex::decode(&bin)
        .map_err(|_| RpcError::InvalidNode("node returned non-hex-encoded block".to_string()))?
        .as_slice(),
    )
    .map_err(|_| RpcError::InvalidNode("node returned invalid block".to_string()))
  }

  /// Fetch a block from the Serai blockchain.
  pub async fn block(&self, block: BlockHash) -> Result<Block, RpcError> {
    Self::block_internal(self.call("blockchain/block", &format!(r#"{{ "block": "{block}" }}"#)))
      .await
  }

  /// Fetch a block from the Serai blockchain by its number.
  pub async fn block_by_number(&self, block: u64) -> Result<Block, RpcError> {
    Self::block_internal(self.call("blockchain/block", &format!(r#"{{ "block": {block} }}"#))).await
  }

  /// Scope this RPC client to the state as of a specific block.
  ///
  /// This will yield an error if the block chosen isn't finalized. This ensures, given an honest
  /// node, that this scope will be available for the lifetime of this object.
  pub async fn as_of<'a>(&'a self, block: BlockHash) -> Result<TemporalSerai<'a>, RpcError> {
    if !self.finalized(block).await? {
      Err(RpcError::NotFinalized)?;
    }
    Ok(TemporalSerai { serai: self, block, events: Arc::new(RwLock::new(None)) })
  }

  /// Return the P2P addresses for the validators of the specified network.
  pub async fn p2p_validators(&self, network: ExternalNetworkId) -> Result<Vec<String>, RpcError> {
    self
      .call(
        "p2p_validators",
        match network {
          ExternalNetworkId::Bitcoin => r#"["bitcoin"]"#,
          ExternalNetworkId::Ethereum => r#"["ethereum"]"#,
          ExternalNetworkId::Monero => r#"["monero"]"#,
          _ => Err(RpcError::InternalError("unrecognized external network ID".to_string()))?,
        },
      )
      .await
  }
}

impl<'a> TemporalSerai<'a> {
  async fn call<ResponseValue: Default + JsonDeserialize>(
    &self,
    method: &str,
    params: &str,
  ) -> Result<ResponseValue, RpcError> {
    self.serai.call(method, &format!(r#"{{ "block": "{}" {params} }}"#, self.block)).await
  }

  /// Fetch the events for this block.
  ///
  /// The returned `Option` will always be `Some(_)`.
  async fn events(&self) -> Result<async_lock::RwLockReadGuard<'_, Option<Vec<Event>>>, RpcError> {
    let mut events = self.events.read().await;
    if events.is_none() {
      drop(events);
      {
        let mut events_mut = self.events.write().await;
        if events_mut.is_none() {
          *events_mut = Some(
            self
              .call::<Vec<String>>("blockchain/events", "")
              .await?
              .into_iter()
              .map(|event| {
                Event::deserialize(
                  &mut hex::decode(&event)
                    .map_err(|_| {
                      RpcError::InvalidNode("node returned non-hex-encoded event".to_string())
                    })?
                    .as_slice(),
                )
                .map_err(|_| RpcError::InvalidNode("node returned invalid event".to_string()))
              })
              .collect::<Result<_, _>>()?,
          );
        }
      }
      events = self.events.read().await;
    }
    Ok(events)
  }

  /// Scope to the validator sets module.
  pub fn validator_sets(&self) -> ValidatorSets<'_> {
    ValidatorSets(self)
  }
}
