use blake2::{
  digest::{consts::U32, Digest},
  Blake2b,
};

use scale::Encode;

use sp_core::Pair;

use serai_client::{
  primitives::insecure_pair_from_name,
  validator_sets::primitives::{Session, ValidatorSet},
  in_instructions::{
    primitives::{Batch, SignedBatch, batch_message},
    InInstructionsEvent,
  },
  SeraiInInstructions,
};

use crate::common::{serai, tx::publish_tx, validator_sets::set_keys};

#[allow(dead_code)]
pub async fn provide_batch(batch: Batch) -> [u8; 32] {
  let serai = serai().await;

  // TODO: Get the latest session
  let set = ValidatorSet { session: Session(0), network: batch.network };
  let pair = insecure_pair_from_name(&format!("ValidatorSet {:?}", set));
  let keys = if let Some(keys) =
    serai.with_current_latest_block().await.unwrap().validator_sets().keys(set).await.unwrap()
  {
    keys
  } else {
    let keys = (pair.public(), vec![].try_into().unwrap());
    set_keys(set, keys.clone()).await;
    keys
  };
  assert_eq!(keys.0, pair.public());

  let block = publish_tx(&SeraiInInstructions::execute_batch(SignedBatch {
    batch: batch.clone(),
    signature: pair.sign(&batch_message(&batch)),
  }))
  .await;

  let batches = serai.as_of(block).in_instructions().batch_events().await.unwrap();
  // TODO: impl From<Batch> for BatchEvent?
  assert_eq!(
    batches,
    vec![InInstructionsEvent::Batch {
      network: batch.network,
      id: batch.id,
      block: batch.block,
      instructions_hash: Blake2b::<U32>::digest(batch.instructions.encode()).into(),
    }],
  );

  // TODO: Check the tokens events

  block
}
