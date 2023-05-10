use serai_runtime::{in_instructions, InInstructions, Runtime};
pub use in_instructions::primitives;
use primitives::SignedBatch;

use subxt::utils::Encoded;

use crate::{
  primitives::{BlockHash, NetworkId},
  SeraiError, Serai, scale_value,
};

pub type InInstructionsEvent = in_instructions::Event<Runtime>;

const PALLET: &str = "InInstructions";

impl Serai {
  pub async fn get_latest_block_for_network(
    &self,
    hash: [u8; 32],
    network: NetworkId,
  ) -> Result<Option<BlockHash>, SeraiError> {
    self.storage(PALLET, "LatestBlock", Some(vec![scale_value(network)]), hash).await
  }

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

  pub fn execute_batch(&self, batch: SignedBatch) -> Encoded {
    self.unsigned::<InInstructions, _>(&in_instructions::Call::<Runtime>::execute_batch { batch })
  }
}
