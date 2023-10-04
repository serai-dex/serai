use rand_core::{RngCore, OsRng};
use blake2::{
  digest::{consts::U32, Digest},
  Blake2b,
};

use scale::Encode;

use sp_core::Pair;

use serai_client::{
  primitives::{insecure_pair_from_name, BlockHash, NetworkId, Balance},
  validator_sets::primitives::{Session, ValidatorSet},
  in_instructions::{
    primitives::{Batch, SignedBatch, batch_message, InInstructionWithBalance, InInstruction},
    InInstructionsEvent,
  },
  Serai, SeraiAddress,
};

use crate::common::{serai, tx::publish_tx, validator_sets::set_validator_set_keys};

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
    set_validator_set_keys(set, keys.clone()).await;
    keys
  };
  assert_eq!(keys.0, pair.public());

  let block = publish_tx(&Serai::execute_batch(SignedBatch {
    batch: batch.clone(),
    signature: pair.sign(&batch_message(&batch)),
  }))
  .await;

  let batches = serai.get_batch_events(block).await.unwrap();
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

#[allow(dead_code)]
pub async fn mint_coin(
  balance: Balance,
  network: NetworkId,
  batch_id: u32,
  address: SeraiAddress,
) -> [u8; 32] {
  let mut block_hash = BlockHash([0; 32]);
  OsRng.fill_bytes(&mut block_hash.0);

  let batch = Batch {
    network,
    id: batch_id,
    block: block_hash,
    instructions: vec![InInstructionWithBalance {
      instruction: InInstruction::Transfer(address),
      balance,
    }],
  };

  provide_batch(batch).await
}
