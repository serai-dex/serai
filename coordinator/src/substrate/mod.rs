use core::{ops::Deref, future::Future};
use std::collections::{HashSet, HashMap};

use zeroize::Zeroizing;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use frost::ThresholdParams;

use serai_client::{
  SeraiError, Block, Serai,
  primitives::BlockHash,
  validator_sets::{
    primitives::{Session, ValidatorSet, KeyPair},
    ValidatorSetsEvent,
  },
  in_instructions::InInstructionsEvent,
  tokens::{primitives::OutInstructionWithBalance, TokensEvent},
};

use serai_db::DbTxn;

use processor_messages::{SubstrateContext, key_gen::KeyGenId, CoordinatorMessage};

use crate::{Db, processor::Processor, tributary::TributarySpec};

mod db;
pub use db::*;

async fn in_set(
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: &Serai,
  set: ValidatorSet,
) -> Result<Option<bool>, SeraiError> {
  let Some(data) = serai.get_validator_set(set).await? else {
    return Ok(None);
  };
  let key = (Ristretto::generator() * key.deref()).to_bytes();
  Ok(Some(data.participants.iter().any(|(participant, _)| participant.0 == key)))
}

async fn handle_new_set<
  D: Db,
  Fut: Future<Output = ()>,
  ANT: Clone + Fn(D, TributarySpec) -> Fut,
  Pro: Processor,
>(
  db: &D,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  add_new_tributary: ANT,
  processor: &mut Pro,
  serai: &Serai,
  block: &Block,
  set: ValidatorSet,
) -> Result<(), SeraiError> {
  if in_set(key, serai, set).await?.expect("NewSet for set which doesn't exist") {
    let set_data = serai.get_validator_set(set).await?.expect("NewSet for set which doesn't exist");

    let spec = TributarySpec::new(block.hash(), block.time().unwrap(), set, set_data);
    add_new_tributary(db.clone(), spec.clone());

    // Trigger a DKG
    // TODO: Check how the processor handles this being fired multiple times
    // We already have a unique event ID based on block, event index (where event index is
    // the one generated in this handle_block function)
    // We could use that on this end and the processor end?
    processor
      .send(CoordinatorMessage::KeyGen(
        processor_messages::key_gen::CoordinatorMessage::GenerateKey {
          id: KeyGenId { set, attempt: 0 },
          params: ThresholdParams::new(
            spec.t(),
            spec.n(),
            spec
              .i(Ristretto::generator() * key.deref())
              .expect("In set for a set we aren't in set for"),
          )
          .unwrap(),
        },
      ))
      .await;
  }

  Ok(())
}

async fn handle_key_gen<Pro: Processor>(
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  processor: &mut Pro,
  serai: &Serai,
  block: &Block,
  set: ValidatorSet,
  key_pair: KeyPair,
) -> Result<(), SeraiError> {
  if in_set(key, serai, set).await?.expect("KeyGen occurred for a set which doesn't exist") {
    // TODO: Check how the processor handles this being fired multiple times
    processor
      .send(CoordinatorMessage::Substrate(
        processor_messages::substrate::CoordinatorMessage::ConfirmKeyPair {
          context: SubstrateContext {
            serai_time: block.time().unwrap(),
            coin_latest_finalized_block: serai
              .get_latest_block_for_network(block.hash(), set.network)
              .await?
              // The processor treats this as a magic value which will cause it to find a network
              // block which has a time greater than or equal to the Serai time
              .unwrap_or(BlockHash([0; 32])),
          },
          set,
          key_pair,
        },
      ))
      .await;
  }

  Ok(())
}

async fn handle_batch_and_burns<Pro: Processor>(
  processor: &mut Pro,
  serai: &Serai,
  block: &Block,
) -> Result<(), SeraiError> {
  let hash = block.hash();

  // Track which networks had events with a Vec in ordr to preserve the insertion order
  // While that shouldn't be needed, ensuring order never hurts, and may enable design choices
  // with regards to Processor <-> Coordinator message passing
  let mut networks_with_event = vec![];
  let mut network_had_event = |burns: &mut HashMap<_, _>, network| {
    // Don't insert this network multiple times
    // A Vec is still used in order to maintain the insertion order
    if !networks_with_event.contains(&network) {
      networks_with_event.push(network);
      burns.insert(network, vec![]);
    }
  };

  let mut batch_block = HashMap::new();
  let mut burns = HashMap::new();

  for batch in serai.get_batch_events(hash).await? {
    if let InInstructionsEvent::Batch { network, id: _, block: network_block } = batch {
      network_had_event(&mut burns, network);

      // Track what Serai acknowledges as the latest block for this network
      // If this Substrate block has multiple batches, the last batch's block will overwrite the
      // prior batches
      // Since batches within a block are guaranteed to be ordered, thanks to their incremental ID,
      // the last batch will be the latest batch, so its block will be the latest block
      // This is just a mild optimization to prevent needing an additional RPC call to grab this
      batch_block.insert(network, network_block);
    } else {
      panic!("Batch event wasn't Batch: {batch:?}");
    }
  }

  for burn in serai.get_burn_events(hash).await? {
    if let TokensEvent::Burn { address: _, balance, instruction } = burn {
      let network = balance.coin.network();
      network_had_event(&mut burns, network);

      // network_had_event should register an entry in burns
      let mut burns_so_far = burns.remove(&network).unwrap();
      burns_so_far.push(OutInstructionWithBalance { balance, instruction });
      burns.insert(network, burns_so_far);
    } else {
      panic!("Burn event wasn't Burn: {burn:?}");
    }
  }

  assert_eq!(HashSet::<&_>::from_iter(networks_with_event.iter()).len(), networks_with_event.len());

  for network in networks_with_event {
    let coin_latest_finalized_block = if let Some(block) = batch_block.remove(&network) {
      block
    } else {
      // If it's had a batch or a burn, it must have had a block acknowledged
      serai
        .get_latest_block_for_network(hash, network)
        .await?
        .expect("network had a batch/burn yet never set a latest block")
    };

    // TODO: Check how the processor handles this being fired multiple times
    processor
      .send(CoordinatorMessage::Substrate(
        processor_messages::substrate::CoordinatorMessage::SubstrateBlock {
          context: SubstrateContext {
            serai_time: block.time().unwrap(),
            coin_latest_finalized_block,
          },
          block: block.number(),
          key: serai
            .get_keys(ValidatorSet { network, session: Session(0) }) // TODO2
            .await?
            .map(|keys| keys.1.into_inner())
            .expect("batch/burn for network which never set keys"),
          burns: burns.remove(&network).unwrap(),
        },
      ))
      .await;
  }

  Ok(())
}

// Handle a specific Substrate block, returning an error when it fails to get data
// (not blocking / holding)
async fn handle_block<
  D: Db,
  Fut: Future<Output = ()>,
  ANT: Clone + Fn(D, TributarySpec) -> Fut,
  Pro: Processor,
>(
  db: &mut SubstrateDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  add_new_tributary: ANT,
  processor: &mut Pro,
  serai: &Serai,
  block: Block,
) -> Result<(), SeraiError> {
  let hash = block.hash();

  // Define an indexed event ID.
  let mut event_id = 0;

  // If a new validator set was activated, create tributary/inform processor to do a DKG
  for new_set in serai.get_new_set_events(hash).await? {
    // Individually mark each event as handled so on reboot, we minimize duplicates
    // Additionally, if the Serai connection also fails 1/100 times, this means a block with 1000
    // events will successfully be incrementally handled (though the Serai connection should be
    // stable)
    if !SubstrateDb::<D>::handled_event(&db.0, hash, event_id) {
      if let ValidatorSetsEvent::NewSet { set } = new_set {
        handle_new_set(&db.0, key, add_new_tributary.clone(), processor, serai, &block, set)
          .await?;
      } else {
        panic!("NewSet event wasn't NewSet: {new_set:?}");
      }
      let mut txn = db.0.txn();
      SubstrateDb::<D>::handle_event(&mut txn, hash, event_id);
      txn.commit();
    }
    event_id += 1;
  }

  // If a key pair was confirmed, inform the processor
  for key_gen in serai.get_key_gen_events(hash).await? {
    if !SubstrateDb::<D>::handled_event(&db.0, hash, event_id) {
      if let ValidatorSetsEvent::KeyGen { set, key_pair } = key_gen {
        handle_key_gen(key, processor, serai, &block, set, key_pair).await?;
      } else {
        panic!("KeyGen event wasn't KeyGen: {key_gen:?}");
      }
      let mut txn = db.0.txn();
      SubstrateDb::<D>::handle_event(&mut txn, hash, event_id);
      txn.commit();
    }
    event_id += 1;
  }

  // Finally, tell the processor of acknowledged blocks/burns
  // This uses a single event as. unlike prior events which individually executed code, all
  // following events share data collection
  // This does break the uniqueness of (hash, event_id) -> one event, yet
  // (network, (hash, event_id)) remains valid as a unique ID for an event
  if !SubstrateDb::<D>::handled_event(&db.0, hash, event_id) {
    handle_batch_and_burns(processor, serai, &block).await?;
  }
  let mut txn = db.0.txn();
  SubstrateDb::<D>::handle_event(&mut txn, hash, event_id);
  txn.commit();

  Ok(())
}

pub async fn handle_new_blocks<
  D: Db,
  Fut: Future<Output = ()>,
  ANT: Clone + Fn(D, TributarySpec) -> Fut,
  Pro: Processor,
>(
  db: &mut SubstrateDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  add_new_tributary: ANT,
  processor: &mut Pro,
  serai: &Serai,
  last_block: &mut u64,
) -> Result<(), SeraiError> {
  // Check if there's been a new Substrate block
  let latest = serai.get_latest_block().await?;
  let latest_number = latest.number();
  if latest_number == *last_block {
    return Ok(());
  }
  let mut latest = Some(latest);

  for b in (*last_block + 1) ..= latest_number {
    handle_block(
      db,
      key,
      add_new_tributary.clone(),
      processor,
      serai,
      if b == latest_number {
        latest.take().unwrap()
      } else {
        serai
          .get_block_by_number(b)
          .await?
          .expect("couldn't get block before the latest finalized block")
      },
    )
    .await?;
    *last_block += 1;
    db.set_last_block(*last_block);
  }

  Ok(())
}
