use thiserror::Error;

use scale::Decode;

use frame_support::traits::PalletInfo as PalletInfoTrait;
use frame_system::Config as SysConfig;
use subxt::{tx::BaseExtrinsicParams, Config, OnlineClient};

use jsonrpsee_core::client::ClientT;
use jsonrpsee_http_client::HttpClientBuilder;

use serai_primitives::NativeAddress;
use serai_runtime::{in_instructions_pallet, Signature, PalletInfo, InInstructions, Runtime};

pub type InInstructionsEvent = in_instructions_pallet::Event<Runtime>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct SeraiConfig;
impl Config for SeraiConfig {
  type BlockNumber = <Runtime as SysConfig>::BlockNumber;

  type Hash = <Runtime as SysConfig>::Hash;
  type Hashing = <Runtime as SysConfig>::Hashing;

  type Index = <Runtime as SysConfig>::Index;
  type AccountId = <Runtime as SysConfig>::AccountId;
  // TODO: Bech32m
  type Address = NativeAddress;

  type Header = <Runtime as SysConfig>::Header;
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

  pub(crate) async fn get_batch_events(
    &self,
    block: [u8; 32],
  ) -> Result<Vec<InInstructionsEvent>, SeraiError> {
    let mut res = vec![];
    for event in
      self.0.events().at(Some(block.into())).await.map_err(|_| SeraiError::RpcError)?.iter()
    {
      let event = event.unwrap();
      if PalletInfo::index::<InInstructions>().unwrap() == usize::from(event.pallet_index()) {
        let mut with_variant: &[u8] =
          &[[event.variant_index()].as_ref(), event.field_bytes()].concat();
        let event = InInstructionsEvent::decode(&mut with_variant).unwrap();
        if matches!(event, InInstructionsEvent::Batch { .. }) {
          res.push(event);
        }
      }
    }
    Ok(res)
  }
}
