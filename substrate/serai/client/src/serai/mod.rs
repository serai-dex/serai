use thiserror::Error;

use scale::{Encode, Decode};
mod scale_value;
pub(crate) use scale_value::{scale_value, scale_composite};
use subxt::ext::scale_value::Value;

use sp_core::{Pair as PairTrait, sr25519::Pair};
use subxt::{
  error::Error as SubxtError,
  utils::Encoded,
  config::{
    substrate::{BlakeTwo256, SubstrateHeader},
    extrinsic_params::{BaseExtrinsicParams, BaseExtrinsicParamsBuilder},
  },
  tx::{Signer, DynamicTxPayload, TxClient},
  Config as SubxtConfig, OnlineClient,
};

pub use serai_runtime::primitives;
use primitives::{Signature, SeraiAddress};

use serai_runtime::{
  system::Config, support::traits::PalletInfo as PalletInfoTrait, PalletInfo, Runtime,
};

pub mod tokens;
pub mod in_instructions;
pub mod validator_sets {
  pub use serai_runtime::validator_sets::primitives;
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Encode, Decode)]
pub struct Tip {
  #[codec(compact)]
  pub tip: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SeraiConfig;
impl SubxtConfig for SeraiConfig {
  type Hash = <Runtime as Config>::Hash;
  type Hasher = BlakeTwo256;

  type Index = <Runtime as Config>::Index;
  type AccountId = <Runtime as Config>::AccountId;
  // TODO: Bech32m
  type Address = SeraiAddress;

  type Header = SubstrateHeader<<Runtime as Config>::BlockNumber, BlakeTwo256>;
  type Signature = Signature;

  type ExtrinsicParams = BaseExtrinsicParams<SeraiConfig, Tip>;
}

#[derive(Error, Debug)]
pub enum SeraiError {
  #[error("failed to communicate with serai: {0}")]
  RpcError(SubxtError),
  #[error("serai-client library was intended for a different runtime version")]
  InvalidRuntime,
}

#[derive(Clone)]
pub struct Serai(OnlineClient<SeraiConfig>);

impl Serai {
  pub async fn new(url: &str) -> Result<Self, SeraiError> {
    Ok(Serai(OnlineClient::<SeraiConfig>::from_url(url).await.map_err(SeraiError::RpcError)?))
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
      .at(Some(block.into()))
      .await
      .map_err(SeraiError::RpcError)?
      .fetch(&address)
      .await
      .map_err(SeraiError::RpcError)?
      .map(|res| R::decode(&mut res.encoded()).map_err(|_| SeraiError::InvalidRuntime))
      .transpose()
  }

  async fn events<P: 'static, E: Decode>(
    &self,
    block: [u8; 32],
    filter: impl Fn(&E) -> bool,
  ) -> Result<Vec<E>, SeraiError> {
    let mut res = vec![];
    for event in self.0.events().at(Some(block.into())).await.map_err(SeraiError::RpcError)?.iter()
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
    Ok(self.0.rpc().finalized_head().await.map_err(SeraiError::RpcError)?.into())
  }

  pub fn sign<S: Send + Sync + Signer<SeraiConfig>>(
    &self,
    signer: &S,
    payload: &DynamicTxPayload<'static>,
    nonce: u32,
    params: BaseExtrinsicParamsBuilder<SeraiConfig, Tip>,
  ) -> Result<Encoded, SeraiError> {
    TxClient::new(self.0.offline())
      .create_signed_with_nonce(payload, signer, nonce, params)
      .map(|tx| Encoded(tx.into_encoded()))
      .map_err(|_| SeraiError::InvalidRuntime)
  }

  pub async fn publish(&self, tx: &Encoded) -> Result<[u8; 32], SeraiError> {
    self.0.rpc().submit_extrinsic(tx).await.map(Into::into).map_err(SeraiError::RpcError)
  }
}

#[derive(Clone)]
pub struct PairSigner(Pair, <SeraiConfig as SubxtConfig>::AccountId);
impl PairSigner {
  pub fn new(pair: Pair) -> Self {
    let id = pair.public();
    PairSigner(pair, id)
  }
}
impl Signer<SeraiConfig> for PairSigner {
  fn account_id(&self) -> &<SeraiConfig as SubxtConfig>::AccountId {
    &self.1
  }
  fn address(&self) -> <SeraiConfig as SubxtConfig>::Address {
    self.1.into()
  }
  fn sign(&self, payload: &[u8]) -> <SeraiConfig as SubxtConfig>::Signature {
    self.0.sign(payload)
  }
}
