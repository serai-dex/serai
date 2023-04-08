use scale::Encode;

use sp_core::Pair;

use serai_client::{
  primitives::insecure_pair_from_name,
  validator_sets::primitives::{Session, ValidatorSet},
  in_instructions::{
    primitives::{Batch, SignedBatch},
    InInstructionsEvent,
  },
};

use crate::common::{serai, tx::publish_tx, validator_sets::vote_in_keys};

#[allow(dead_code)]
pub async fn provide_batch(batch: Batch) -> [u8; 32] {
  let serai = serai().await;

  // TODO: Get the latest session
  let set = ValidatorSet { session: Session(0), network: batch.network };
  let pair = insecure_pair_from_name(&format!("ValidatorSet {:?}", set));
  let keys = if let Some(keys) = serai.get_keys(set).await.unwrap() {
    keys
  } else {
    let keys = (pair.public(), vec![].try_into().unwrap());
    vote_in_keys(set, keys.clone()).await;
    keys
  };
  assert_eq!(keys.0, pair.public());

  let block = publish_tx(
    &serai
      .execute_batch(SignedBatch { batch: batch.clone(), signature: pair.sign(&batch.encode()) })
      .unwrap(),
  )
  .await;

  let batches = serai.get_batch_events(block).await.unwrap();
  // TODO: impl From<Batch> for BatchEvent?
  assert_eq!(
    batches,
    vec![InInstructionsEvent::Batch { network: batch.network, id: batch.id, block: batch.block }],
  );

  // TODO: Check the tokens events

  block
}
