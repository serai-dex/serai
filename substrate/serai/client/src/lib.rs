use thiserror::Error;

use scale::Decode;
use serde::Serialize;
use scale_value::Value;

use subxt::{tx::BaseExtrinsicParams, Config as SubxtConfig, OnlineClient};

pub use serai_primitives as primitives;
use primitives::{Signature, SeraiAddress};

use serai_runtime::{
  system::Config, support::traits::PalletInfo as PalletInfoTrait, PalletInfo, Runtime,
};

pub mod tokens;
pub mod in_instructions;

fn scale_value<K: Serialize>(key: K) -> Value {
  scale_value::serde::to_value(key).unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct SeraiConfig;
impl SubxtConfig for SeraiConfig {
  type BlockNumber = <Runtime as Config>::BlockNumber;

  type Hash = <Runtime as Config>::Hash;
  type Hashing = <Runtime as Config>::Hashing;

  type Index = <Runtime as Config>::Index;
  type AccountId = <Runtime as Config>::AccountId;
  // TODO: Bech32m
  type Address = SeraiAddress;

  type Header = <Runtime as Config>::Header;
  type Signature = Signature;

  type ExtrinsicParams = BaseExtrinsicParams<SeraiConfig, ()>;
}

#[derive(Clone, Error, Debug)]
pub enum SeraiError {
  #[error("failed to connect to serai")]
  RpcError,
  #[error("serai-client library was intended for a different runtime version")]
  InvalidRuntime,
}

#[derive(Clone)]
pub struct Serai(OnlineClient<SeraiConfig>);

impl Serai {
  pub async fn new(url: &str) -> Result<Self, SeraiError> {
    Ok(Serai(OnlineClient::<SeraiConfig>::from_url(url).await.map_err(|_| SeraiError::RpcError)?))
  }

  async fn storage<R: Decode>(
    &self,
    pallet: &'static str,
    name: &'static str,
    keys: Option<Vec<Value>>,
    block: [u8; 32],
  ) -> Result<Option<R>, SeraiError> {
    let storage = self.0.storage();
    let address = subxt::dynamic::storage(pallet, name, keys.unwrap_or(vec![]));
    debug_assert!(storage.validate(&address).is_ok(), "invalid storage address");

    storage
      .fetch(&address, Some(block.into()))
      .await
      .map_err(|e| {
        dbg!(e);
        SeraiError::RpcError
      })?
      .map(|res| R::decode(&mut res.encoded()).map_err(|_| SeraiError::InvalidRuntime))
      .transpose()
  }

  async fn events<P: 'static, E: Decode>(
    &self,
    block: [u8; 32],
    filter: impl Fn(&E) -> bool,
  ) -> Result<Vec<E>, SeraiError> {
    let mut res = vec![];
    for event in
      self.0.events().at(Some(block.into())).await.map_err(|_| SeraiError::RpcError)?.iter()
    {
      let event = event.map_err(|_| SeraiError::InvalidRuntime)?;
      if PalletInfo::index::<P>().unwrap() == usize::from(event.pallet_index()) {
        let mut with_variant: &[u8] =
          &[[event.variant_index()].as_ref(), event.field_bytes()].concat();
        let event = E::decode(&mut with_variant).map_err(|_| SeraiError::InvalidRuntime)?;
        if filter(&event) {
          res.push(event);
        }
      }
    }
    Ok(res)
  }

  pub async fn get_latest_block_hash(&self) -> Result<[u8; 32], SeraiError> {
    Ok(self.0.rpc().finalized_head().await.map_err(|_| SeraiError::RpcError)?.into())
  }
}
