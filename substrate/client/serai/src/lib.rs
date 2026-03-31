#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

use core::future::Future;
use std::{sync::Arc, io::Read as _};

use thiserror::Error;
use core_json_traits::{JsonDeserialize, JsonStructure as _};
use core_json_derive::JsonDeserialize;
use simple_request::{hyper, TokioClient};

use borsh::BorshDeserialize as _;
pub use serai_abi as abi;
use abi::{
  primitives::{
    BlockHash,
    network_id::ExternalNetworkId,
    coin::{Coin, ExternalCoin},
  },
  Transaction, Block, Event,
};

mod coins;
pub use coins::Coins;

mod dex;
mod liquidity_tokens;
mod genesis_liquidity;

mod validator_sets;
pub use validator_sets::ValidatorSets;

mod in_instructions;
pub use in_instructions::InInstructions;

pub(crate) fn rpc_coin(network: impl Into<Coin>) -> &'static str {
  match network.into() {
    Coin::Serai => r#""SRI""#,
    Coin::External(ExternalCoin::Bitcoin) => r#""BTC""#,
    Coin::External(ExternalCoin::Ether) => r#""ETH""#,
    Coin::External(ExternalCoin::Dai) => r#""DAI""#,
    Coin::External(ExternalCoin::Monero) => r#""XMR""#,
  }
}

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

/// The events from a specific block.
#[derive(Clone)]
pub struct Events {
  // These are cached within an `Arc` for cheap `Clone`s
  events: Arc<Vec<Vec<Event>>>,
}

/// An RPC client to a Serai node, scoped to a specific block.
#[derive(Clone)]
pub struct State<'serai> {
  serai: &'serai Serai,
  block: BlockHash,
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
      RpcError::InternalError("couldn't read response from `simple-request` into `Vec`".to_owned())
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
        Err(RpcError::InvalidNode("node didn't provided both `result` and `error`".to_owned()))
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
    block: impl Future<Output = Result<Option<String>, RpcError>>,
  ) -> Result<Option<Block>, RpcError> {
    let bin = block.await?;
    bin
      .map(|bin| {
        Block::deserialize(
          &mut hex::decode(&bin)
            .map_err(|_| RpcError::InvalidNode("node returned non-hex-encoded block".to_owned()))?
            .as_slice(),
        )
        .map_err(|_| RpcError::InvalidNode("node returned invalid block".to_owned()))
      })
      .transpose()
  }

  /// Fetch a block from the Serai blockchain.
  pub async fn block(&self, block: BlockHash) -> Result<Option<Block>, RpcError> {
    Self::block_internal(self.call("blockchain/block", &format!(r#"{{ "block": "{block}" }}"#)))
      .await
  }

  /// Fetch a block from the Serai blockchain by its number.
  pub async fn block_by_number(&self, block: u64) -> Result<Option<Block>, RpcError> {
    Self::block_internal(self.call("blockchain/block", &format!(r#"{{ "block": {block} }}"#))).await
  }

  /// Publish a transaction onto the Serai blockchain.
  pub async fn publish_transaction(&self, transaction: &Transaction) -> Result<(), RpcError> {
    self
      .call(
        "blockchain/publish_transaction",
        &format!(r#"{{ "transaction": {} }}"#, hex::encode(borsh::to_vec(transaction).unwrap())),
      )
      .await
  }

  /// Fetch the events of a specific block.
  pub async fn events(&self, block: BlockHash) -> Result<Events, RpcError> {
    Ok(Events {
      events: Arc::new(
        self
          .call::<Vec<Vec<String>>>("blockchain/events", &format!(r#"{{ "block": "{block}" }}"#))
          .await?
          .into_iter()
          .map(|events_per_tx| {
            events_per_tx
              .into_iter()
              .map(|event| {
                Event::deserialize(
                  &mut hex::decode(&event)
                    .map_err(|_| {
                      RpcError::InvalidNode("node returned non-hex-encoded event".to_owned())
                    })?
                    .as_slice(),
                )
                .map_err(|_| RpcError::InvalidNode("node returned invalid event".to_owned()))
              })
              .collect::<Result<Vec<_>, _>>()
          })
          .collect::<Result<Vec<_>, _>>()?,
      ),
    })
  }

  /// Scope this RPC client to the state as of the latest finalized block.
  pub async fn state(&self) -> Result<State<'_>, RpcError> {
    let block = self
      .block_by_number(self.latest_finalized_block_number().await?)
      .await?
      .ok_or_else(|| RpcError::InvalidNode("couldn't fetch latest finalized block".to_owned()))?;
    Ok(State { serai: self, block: block.header.hash() })
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
        },
      )
      .await
  }
}

impl Events {
  /// The events within this container.
  ///
  /// This will yield the events for each transaction within the block, including the implicit
  /// transactions at the start and end of each block, within an outer container.
  pub fn events(&self) -> impl Iterator<Item: IntoIterator<Item = &Event>> {
    self.events.iter()
  }

  /// Scope to the coins module.
  pub fn coins(&self) -> Coins {
    Coins(self.clone())
  }

  /// Scope to the validator sets module.
  pub fn validator_sets(&self) -> ValidatorSets {
    ValidatorSets(self.clone())
  }

  /// Scope to the in instructions module.
  pub fn in_instructions(&self) -> InInstructions {
    InInstructions(self.clone())
  }
}

impl State<'_> {
  async fn call<ResponseValue: Default + JsonDeserialize>(
    &self,
    method: &str,
    params: &str,
  ) -> Result<ResponseValue, RpcError> {
    self.serai.call(method, &format!(r#"{{ "block": "{}" {params} }}"#, self.block)).await
  }
}
