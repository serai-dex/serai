use serai_runtime::{in_instructions, InInstructions, Runtime};
pub use in_instructions::primitives;
use primitives::SignedBatch;

use subxt::utils::Encoded;

use crate::{Serai, SeraiError};

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

  pub fn execute_batch(&self, batch: SignedBatch) -> Result<Encoded, SeraiError> {
    self.unsigned::<InInstructions, _>(&in_instructions::Call::<Runtime>::execute_batch { batch })
  }
}
