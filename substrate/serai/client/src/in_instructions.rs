use scale::Decode;

use serai_runtime::{
  support::traits::PalletInfo as PalletInfoTrait, PalletInfo, in_instructions, InInstructions,
  Runtime,
};

pub use in_instructions_primitives as primitives;

use crate::{
  primitives::{Coin, BlockNumber},
  Serai, SeraiError,
};

const PALLET: &str = "InInstructions";

pub type InInstructionsEvent = in_instructions::Event<Runtime>;

impl Serai {
  pub async fn get_batch_events(
    &self,
    block: [u8; 32],
  ) -> Result<Vec<InInstructionsEvent>, SeraiError> {
    let mut res = vec![];
    for event in
      self.0.events().at(Some(block.into())).await.map_err(|_| SeraiError::RpcError)?.iter()
    {
      let event = event.map_err(|_| SeraiError::InvalidRuntime)?;
      if PalletInfo::index::<InInstructions>().unwrap() == usize::from(event.pallet_index()) {
        let mut with_variant: &[u8] =
          &[[event.variant_index()].as_ref(), event.field_bytes()].concat();
        let event =
          InInstructionsEvent::decode(&mut with_variant).map_err(|_| SeraiError::InvalidRuntime)?;
        if matches!(event, InInstructionsEvent::Batch { .. }) {
          res.push(event);
        }
      }
    }
    Ok(res)
  }

  pub async fn get_coin_block_number(
    &self,
    coin: Coin,
    block: [u8; 32],
  ) -> Result<BlockNumber, SeraiError> {
    Ok(self.storage(PALLET, "BlockNumbers", Some(coin), block).await?.unwrap_or(BlockNumber(0)))
  }

  pub async fn get_next_batch_id(&self, coin: Coin, block: [u8; 32]) -> Result<u64, SeraiError> {
    Ok(self.storage(PALLET, "NextBatch", Some(coin), block).await?.unwrap_or(0))
  }
}
