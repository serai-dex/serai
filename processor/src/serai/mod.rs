use thiserror::Error;

use frame_system::Config as SysConfig;
use subxt::{
  Config, ClientBuilder,
  extrinsic::BaseExtrinsicParams,
  events::{EventSubscription, FilterEvents},
  rpc::Subscription,
};

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
}

include!(concat!(env!("OUT_DIR"), "/runtime.rs"));

pub(crate) type Events<'a> =
  EventSubscription<'a, Subscription<<SeraiConfig as Config>::Header>, SeraiConfig, runtime::Event>;
pub(crate) type Filter<T> = (T,);
pub(crate) type Event<'a, T> = FilterEvents<'a, Events<'a>, SeraiConfig, Filter<T>>;

pub(crate) type Batch = runtime::in_instructions::events::Batch;

type SeraiXt = runtime::RuntimeApi<SeraiConfig, BaseExtrinsicParams<SeraiConfig, ()>>;

#[derive(Clone, Error, Debug)]
pub(crate) enum SeraiError {
  #[error("failed to connect to serai")]
  RpcError,
}

pub(crate) struct Serai(SeraiXt);

impl Serai {
  pub(crate) async fn new() -> Serai {
    Serai(ClientBuilder::new().build().await.unwrap().to_runtime_api::<SeraiXt>())
  }

  pub(crate) async fn batches(&self) -> Result<Event<Batch>, SeraiError> {
    Ok(
      self
        .0
        .events()
        .subscribe()
        .await
        .map_err(|_| SeraiError::RpcError)?
        .filter_events::<Filter<Batch>>(),
    )
  }
}
