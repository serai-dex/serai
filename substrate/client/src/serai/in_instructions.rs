pub use serai_abi::in_instructions::primitives;
use primitives::SignedBatch;

use crate::{
  primitives::{BlockHash, NetworkId},
  Transaction, SeraiError, Serai, TemporalSerai,
};

pub type InInstructionsEvent = serai_abi::in_instructions::Event;

const PALLET: &str = "InInstructions";

#[derive(Clone, Copy)]
pub struct SeraiInInstructions<'a>(pub(crate) &'a TemporalSerai<'a>);
impl<'a> SeraiInInstructions<'a> {
  pub async fn latest_block_for_network(
    &self,
    network: NetworkId,
  ) -> Result<Option<BlockHash>, SeraiError> {
    self.0.storage(PALLET, "LatestNetworkBlock", network).await
  }

  pub async fn last_batch_for_network(
    &self,
    network: NetworkId,
  ) -> Result<Option<u32>, SeraiError> {
    self.0.storage(PALLET, "LastBatch", network).await
  }

  pub async fn batch_events(&self) -> Result<Vec<InInstructionsEvent>, SeraiError> {
    self
      .0
      .events(|event| {
        if let serai_abi::Event::InInstructions(event) = event {
          if matches!(event, InInstructionsEvent::Batch { .. }) {
            Some(event.clone())
          } else {
            None
          }
        } else {
          None
        }
      })
      .await
  }

  pub fn execute_batch(batch: SignedBatch) -> Transaction {
    Serai::unsigned(serai_abi::Call::InInstructions(
      serai_abi::in_instructions::Call::execute_batch { batch },
    ))
  }
}
