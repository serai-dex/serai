use serai_runtime::{in_instructions, InInstructions, Runtime};
pub use in_instructions::primitives;

use crate::{
  primitives::{Coin, BlockNumber},
  Serai, SeraiError, scale_value,
};

const PALLET: &str = "InInstructions";

pub type InInstructionsEvent = in_instructions::Event<Runtime>;

impl Serai {
  pub async fn get_batch_events(
    &self,
    block: [u8; 32],
  ) -> Result<Vec<InInstructionsEvent>, SeraiError> {
    self
      .events::<InInstructions, _>(block, |event| {
        matches!(event, InInstructionsEvent::Batch { .. })
      })
      .await
  }

  pub async fn get_coin_block_number(
    &self,
    coin: Coin,
    block: [u8; 32],
  ) -> Result<BlockNumber, SeraiError> {
    Ok(
      self
        .storage(PALLET, "BlockNumbers", Some(vec![scale_value(coin)]), block)
        .await?
        .unwrap_or(BlockNumber(0)),
    )
  }
}
