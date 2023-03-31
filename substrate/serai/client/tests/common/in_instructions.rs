use serai_client::in_instructions::{primitives::SignedBatch, InInstructionsEvent};

use crate::common::{serai, tx::publish_tx};

#[allow(dead_code)]
pub async fn provide_batch(batch: SignedBatch) -> [u8; 32] {
  let serai = serai().await;

  let execution = serai.execute_batch(batch.clone()).unwrap();
  let block = publish_tx(&execution).await;

  let batches = serai.get_batch_events(block).await.unwrap();
  // TODO: impl From<Batch> for BatchEvent?
  assert_eq!(
    batches,
    vec![InInstructionsEvent::Batch {
      network: batch.batch.network,
      id: batch.batch.id,
      block: batch.batch.block,
    }],
  );

  // TODO: Check the tokens events

  block
}
