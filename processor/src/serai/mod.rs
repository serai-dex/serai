use thiserror::Error;

use scale::Decode;

use serai_runtime::{
  primitives::{Signature, NativeAddress},
  support::traits::PalletInfo as PalletInfoTrait,
  PalletInfo,
  system::Config,
  in_instructions, InInstructions, Runtime,
};

use subxt::{tx::BaseExtrinsicParams, Config as SubxtConfig, OnlineClient};

pub type InInstructionsEvent = in_instructions::Event<Runtime>;

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
  pub(crate) async fn new() -> Result<Self, SeraiError> {
    Ok(Serai(
      OnlineClient::<SeraiConfig>::from_url("ws://127.0.0.1:9944")
        .await
        .map_err(|_| SeraiError::RpcError)?,
    ))
  }

  // Doesn't use subxt as we can't have multiple connections through it yet a global subxt requires
  // unsafe. Directly implementing this primitve allows us to not require multiple subxts
  pub(crate) async fn get_latest_block_hash(&self) -> Result<[u8; 32], SeraiError> {
    Ok(self.0.rpc().finalized_head().await.map_err(|_| SeraiError::RpcError)?.into())
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
