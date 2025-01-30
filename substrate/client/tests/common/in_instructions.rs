use rand_core::{RngCore, OsRng};
use blake2::{
  digest::{consts::U32, Digest},
  Blake2b,
};

use scale::Encode;

use sp_core::Pair;

use serai_client::{
  primitives::{BlockHash, ExternalBalance, SeraiAddress, insecure_pair_from_name},
  validator_sets::primitives::{ExternalValidatorSet, KeyPair},
  in_instructions::{
    primitives::{Batch, SignedBatch, batch_message, InInstruction, InInstructionWithBalance},
    InInstructionsEvent,
  },
  SeraiInInstructions, Serai,
};

use crate::common::{tx::publish_tx, validator_sets::set_keys};

#[allow(dead_code)]
pub async fn provide_batch(serai: &Serai, batch: Batch) -> [u8; 32] {
  let serai_latest = serai.as_of_latest_finalized_block().await.unwrap();
  let session = serai_latest.validator_sets().session(batch.network.into()).await.unwrap().unwrap();
  let set = ExternalValidatorSet { session, network: batch.network };

  let pair = insecure_pair_from_name(&format!("ValidatorSet {set:?}"));
  let keys = if let Some(keys) = serai_latest.validator_sets().keys(set).await.unwrap() {
    keys
  } else {
    let keys = KeyPair(pair.public(), vec![].try_into().unwrap());
    set_keys(serai, set, keys.clone(), &[insecure_pair_from_name("Alice")]).await;
    keys
  };
  assert_eq!(keys.0, pair.public());

  let block = publish_tx(
    serai,
    &SeraiInInstructions::execute_batch(SignedBatch {
      batch: batch.clone(),
      signature: pair.sign(&batch_message(&batch)),
    }),
  )
  .await;

  {
    let mut batches = serai.as_of(block).in_instructions().batch_events().await.unwrap();
    assert_eq!(batches.len(), 1);
    let InInstructionsEvent::Batch {
      network,
      publishing_session,
      id,
      external_network_block_hash,
      in_instructions_hash,
      in_instruction_results: _,
    } = batches.swap_remove(0)
    else {
      panic!("Batch event wasn't Batch event")
    };
    assert_eq!(network, batch.network);
    assert_eq!(publishing_session, session);
    assert_eq!(id, batch.id);
    assert_eq!(external_network_block_hash, batch.external_network_block_hash);
    assert_eq!(
      in_instructions_hash,
      <[u8; 32]>::from(Blake2b::<U32>::digest(batch.instructions.encode()))
    );
  }

  // TODO: Check the tokens events

  block
}

#[allow(dead_code)]
pub async fn mint_coin(
  serai: &Serai,
  balance: ExternalBalance,
  batch_id: u32,
  address: SeraiAddress,
) -> [u8; 32] {
  let mut block_hash = BlockHash([0; 32]);
  OsRng.fill_bytes(&mut block_hash.0);

  let batch = Batch {
    network: balance.coin.network(),
    id: batch_id,
    external_network_block_hash: block_hash,
    instructions: vec![InInstructionWithBalance {
      instruction: InInstruction::Transfer(address),
      balance,
    }],
  };

  provide_batch(serai, batch).await
}
