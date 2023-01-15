use thiserror::Error;

use serde::Serialize;
use scale::Decode;

use serai_runtime::{
  primitives::{Signature, NativeAddress},
  system::Config,
  Runtime,
};

use subxt::{tx::BaseExtrinsicParams, Config as SubxtConfig, OnlineClient};

mod in_instructions;
pub use in_instructions::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct SeraiConfig;
impl SubxtConfig for SeraiConfig {
  type BlockNumber = <Runtime as Config>::BlockNumber;

  type Hash = <Runtime as Config>::Hash;
  type Hashing = <Runtime as Config>::Hashing;

  type Index = <Runtime as Config>::Index;
  type AccountId = <Runtime as Config>::AccountId;
  // TODO: Bech32m
  type Address = NativeAddress;

  type Header = <Runtime as Config>::Header;
  type Signature = Signature;

  type ExtrinsicParams = BaseExtrinsicParams<SeraiConfig, ()>;
}

#[derive(Clone, Error, Debug)]
pub(crate) enum SeraiError {
  #[error("failed to connect to serai")]
  RpcError,
}

#[derive(Clone)]
pub(crate) struct Serai(OnlineClient<SeraiConfig>);

impl Serai {
  pub async fn new() -> Result<Self, SeraiError> {
    Ok(Serai(
      OnlineClient::<SeraiConfig>::from_url("ws://127.0.0.1:9944")
        .await
        .map_err(|_| SeraiError::RpcError)?,
    ))
  }

  async fn storage<K: Serialize, R: Decode>(
    &self,
    pallet: &'static str,
    name: &'static str,
    key: Option<K>,
    block: [u8; 32],
  ) -> Result<Option<R>, SeraiError> {
    /*
    let mut registry = scale_info::Registry::new();
    registry.register_type(&MetaType::<K>::new());
    let registry = scale_value::scale::PortableRegistry::from(registry);
    scale_value::decode_as_type(&mut &key.encode(), core::any::type_id::<K>(), &registry)
    */
    let mut keys = vec![];
    if let Some(key) = key {
      keys.push(scale_value::serde::to_value(key).unwrap());
    }

    let storage = self.0.storage();
    let address = subxt::dynamic::storage(pallet, name, keys);
    debug_assert!(storage.validate(&address).is_ok());

    Ok(
      storage
        .fetch(&address, Some(block.into()))
        .await
        .map_err(|_| SeraiError::RpcError)?
        .map(|res| R::decode(&mut res.encoded()).unwrap()),
    )
  }

  pub async fn get_latest_block_hash(&self) -> Result<[u8; 32], SeraiError> {
    Ok(self.0.rpc().finalized_head().await.map_err(|_| SeraiError::RpcError)?.into())
  }
}
