use thiserror::Error;

use frame_system::Config as SysConfig;
use subxt::{tx::BaseExtrinsicParams, Config, OnlineClient};

use jsonrpsee_core::client::ClientT;
use jsonrpsee_http_client::HttpClientBuilder;

use serai_runtime::{Address, Signature, Runtime};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct SeraiConfig;
impl Config for SeraiConfig {
  type BlockNumber = <Runtime as SysConfig>::BlockNumber;

  type Hash = <Runtime as SysConfig>::Hash;
  type Hashing = <Runtime as SysConfig>::Hashing;

  type Index = <Runtime as SysConfig>::Index;
  type AccountId = <Runtime as SysConfig>::AccountId;
  // TODO: Bech32m
  type Address = Address;

  type Header = <Runtime as SysConfig>::Header;
  type Signature = Signature;

  type ExtrinsicParams = BaseExtrinsicParams<SeraiConfig, ()>;
}

include!(concat!(env!("OUT_DIR"), "/runtime.rs"));

use runtime::in_instructions::events::Batch;

#[derive(Clone, Error, Debug)]
pub(crate) enum SeraiError {
  #[error("failed to connect to serai")]
  RpcError,
}

#[derive(Clone)]
pub(crate) struct Serai(OnlineClient<SeraiConfig>);

impl Serai {
  pub(crate) async fn new() -> Self {
    Serai(OnlineClient::<SeraiConfig>::from_url("ws://127.0.0.1:9944").await.unwrap())
  }

  // Doesn't use subxt as we can't have multiple connections through it yet a global subxt requires
  // unsafe. Directly implementing this primitve allows us to not require multiple subxts
  pub(crate) async fn get_latest_block_hash() -> Result<[u8; 32], SeraiError> {
    let hash: <SeraiConfig as Config>::Hash = HttpClientBuilder::default()
      .build("http://127.0.0.1:9933")
      .map_err(|_| SeraiError::RpcError)?
      .request("chain_getFinalizedHead", Vec::<u8>::new())
      .await
      .map_err(|_| SeraiError::RpcError)?;
    Ok(hash.into())
  }

  pub(crate) async fn get_batches(&self, block: [u8; 32]) -> Result<Option<Batch>, SeraiError> {
    let events = self.0.events().at(Some(block.into())).await.map_err(|_| SeraiError::RpcError)?;
    let mut batches =
      events.find::<Batch>().collect::<Result<Vec<_>, _>>().map_err(|_| SeraiError::RpcError)?;
    debug_assert!(batches.len() <= 1);
    Ok(batches.pop())
  }
}
