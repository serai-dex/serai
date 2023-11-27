use serai_runtime::{in_instructions, Runtime};
pub use in_instructions::primitives;
use primitives::SignedBatch;

use crate::{
  primitives::{BlockHash, NetworkId},
  SeraiError, Serai, TemporalSerai,
};

pub type InInstructionsEvent = in_instructions::Event<Runtime>;

const PALLET: &str = "InInstructions";

#[derive(Clone, Copy)]
pub struct SeraiInInstructions<'a>(pub(crate) TemporalSerai<'a>);
impl<'a> SeraiInInstructions<'a> {
  pub fn into_inner(self) -> TemporalSerai<'a> {
    self.0
  }

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
        if let serai_runtime::RuntimeEvent::InInstructions(event) = event {
          Some(event).filter(|event| matches!(event, InInstructionsEvent::Batch { .. }))
        } else {
          None
        }
      })
      .await
  }

  pub fn execute_batch(batch: SignedBatch) -> Vec<u8> {
    Serai::unsigned(&serai_runtime::RuntimeCall::InInstructions(
      in_instructions::Call::<Runtime>::execute_batch { batch },
    ))
  }
}
