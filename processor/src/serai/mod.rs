use thiserror::Error;

use frame_system::Config as SysConfig;
use subxt::{
  tx::BaseExtrinsicParams,
  events::{EventSubscription, FilterEvents},
  rpc::Subscription,
  Config, OnlineClient,
};

use jsonrpsee_core::client::ClientT;
use jsonrpsee_http_client::HttpClientBuilder;

use serai_runtime::{Address, Signature, UncheckedExtrinsic, Runtime};

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

  type Extrinsic = UncheckedExtrinsic;
  type ExtrinsicParams = BaseExtrinsicParams<SeraiConfig, ()>;
}

include!(concat!(env!("OUT_DIR"), "/runtime.rs"));

pub(crate) type Events = EventSubscription<
  SeraiConfig,
  OnlineClient<SeraiConfig>,
  Subscription<<SeraiConfig as Config>::Header>,
>;
pub(crate) type Filter<T> = (T,);
pub(crate) type Event<'a, T> = FilterEvents<'a, Events, SeraiConfig, Filter<T>>;

pub(crate) type Batch = runtime::in_instructions::events::Batch;

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
  pub(crate) async fn height() -> Result<u32, SeraiError> {
    let header: <SeraiConfig as Config>::Header = HttpClientBuilder::default()
      .build("http://127.0.0.1:9933")
      .map_err(|_| SeraiError::RpcError)?
      // TODO: Replace with getFinalizedHead
      .request("chain_getHeader", None)
      .await
      .map_err(|_| SeraiError::RpcError)?;
    Ok(header.number)
  }

  pub(crate) async fn batches(&self) -> Result<Event<Batch>, SeraiError> {
    Ok(
      self
        .0
        .events()
        .subscribe() // TODO: subscribe_finalized
        .await
        .map_err(|_| SeraiError::RpcError)?
        .filter_events::<Filter<Batch>>(),
    )
  }
}
