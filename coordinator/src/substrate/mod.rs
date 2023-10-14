use core::{ops::Deref, time::Duration};
use std::collections::{HashSet, HashMap};

use zeroize::Zeroizing;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use serai_client::{
  SeraiError, Block, Serai,
  primitives::{BlockHash, NetworkId},
  validator_sets::{
    primitives::{ValidatorSet, KeyPair, amortize_excess_key_shares},
    ValidatorSetsEvent,
  },
  in_instructions::InInstructionsEvent,
  tokens::{primitives::OutInstructionWithBalance, TokensEvent},
};

use serai_db::DbTxn;

use processor_messages::SubstrateContext;

use tokio::time::sleep;

use crate::{
  Db,
  processors::Processors,
  tributary::{TributarySpec, TributaryDb},
};

mod db;
pub use db::*;

async fn in_set(
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: &Serai,
  set: ValidatorSet,
  block_hash: [u8; 32],
) -> Result<Option<bool>, SeraiError> {
  let Some(participants) = serai.get_validator_set_participants(set.network, block_hash).await?
  else {
    return Ok(None);
  };
  let key = (Ristretto::generator() * key.deref()).to_bytes();
  Ok(Some(participants.iter().any(|participant| participant.0 == key)))
}

async fn handle_new_set<D: Db, CNT: Clone + Fn(&mut D, TributarySpec)>(
  db: &mut D,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  create_new_tributary: CNT,
  serai: &Serai,
  block: &Block,
  set: ValidatorSet,
) -> Result<(), SeraiError> {
  if in_set(key, serai, set, block.hash()).await?.expect("NewSet for set which doesn't exist") {
    log::info!("present in set {:?}", set);

    let set_participants = serai
      .get_validator_set_participants(set.network, block.hash())
      .await?
      .expect("NewSet for set which doesn't exist");

    let allocation_per_key_share = serai
      .get_allocation_per_key_share(set.network, block.hash())
      .await?
      .expect("NewSet for set which didn't have an allocation per key share")
      .0;

    let mut set_data = vec![];
    for participant in set_participants {
      let allocation = serai
        .get_allocation(set.network, participant, block.hash())
        .await?
        .expect("validator selected for set yet didn't have an allocation")
        .0;
      set_data.push((participant, allocation / allocation_per_key_share));
    }
    amortize_excess_key_shares(&mut set_data);

    let time = if let Ok(time) = block.time() {
      time
    } else {
      assert_eq!(block.number(), 0);
      // Use the next block's time
      loop {
        let Ok(Some(res)) = serai.get_block_by_number(1).await else {
          sleep(Duration::from_secs(5)).await;
          continue;
        };
        break res.time().unwrap();
      }
    };
    // The block time is in milliseconds yet the Tributary is in seconds
    let time = time / 1000;
    // Since this block is in the past, and Tendermint doesn't play nice with starting chains after
    // their start time (though it does eventually work), delay the start time by 120 seconds
    // This is meant to handle ~20 blocks of lack of finalization for this first block
    const SUBSTRATE_TO_TRIBUTARY_TIME_DELAY: u64 = 120;
    let time = time + SUBSTRATE_TO_TRIBUTARY_TIME_DELAY;

    let spec = TributarySpec::new(block.hash(), time, set, set_data);
    create_new_tributary(db, spec.clone());
  } else {
    log::info!("not present in set {:?}", set);
  }

  Ok(())
}

async fn handle_key_gen<D: Db, Pro: Processors>(
  db: &mut D,
  processors: &Pro,
  serai: &Serai,
  block: &Block,
  set: ValidatorSet,
  key_pair: KeyPair,
) -> Result<(), SeraiError> {
  // This has to be saved *before* we send ConfirmKeyPair
  let mut txn = db.txn();
  SubstrateDb::<D>::save_session_for_keys(&mut txn, &key_pair, set.session);
  txn.commit();

  processors
    .send(
      set.network,
      processor_messages::substrate::CoordinatorMessage::ConfirmKeyPair {
        context: SubstrateContext {
          serai_time: block.time().unwrap() / 1000,
          network_latest_finalized_block: serai
            .get_latest_block_for_network(block.hash(), set.network)
            .await?
            // The processor treats this as a magic value which will cause it to find a network
            // block which has a time greater than or equal to the Serai time
            .unwrap_or(BlockHash([0; 32])),
        },
        set,
        key_pair,
      },
    )
    .await;

  Ok(())
}

async fn handle_batch_and_burns<D: Db, Pro: Processors>(
  db: &mut D,
  processors: &Pro,
  serai: &Serai,
  block: &Block,
) -> Result<(), SeraiError> {
  let hash = block.hash();

  // Track which networks had events with a Vec in ordr to preserve the insertion order
  // While that shouldn't be needed, ensuring order never hurts, and may enable design choices
  // with regards to Processor <-> Coordinator message passing
  let mut networks_with_event = vec![];
  let mut network_had_event = |burns: &mut HashMap<_, _>, batches: &mut HashMap<_, _>, network| {
    // Don't insert this network multiple times
    // A Vec is still used in order to maintain the insertion order
    if !networks_with_event.contains(&network) {
      networks_with_event.push(network);
      burns.insert(network, vec![]);
      batches.insert(network, vec![]);
    }
  };

  let mut batch_block = HashMap::new();
  let mut batches = HashMap::<NetworkId, Vec<u32>>::new();
  let mut burns = HashMap::new();

  for batch in serai.get_batch_events(hash).await? {
    if let InInstructionsEvent::Batch { network, id, block: network_block, instructions_hash } =
      batch
    {
      network_had_event(&mut burns, &mut batches, network);

      let mut txn = db.txn();
      SubstrateDb::<D>::save_batch_instructions_hash(&mut txn, network, id, instructions_hash);
      txn.commit();

      // Make sure this is the only Batch event for this network in this Block
      assert!(batch_block.insert(network, network_block).is_none());

      // Add the batch included by this block
      batches.get_mut(&network).unwrap().push(id);
    } else {
      panic!("Batch event wasn't Batch: {batch:?}");
    }
  }

  for burn in serai.get_burn_events(hash).await? {
    if let TokensEvent::Burn { address: _, balance, instruction } = burn {
      let network = balance.coin.network();
      network_had_event(&mut burns, &mut batches, network);

      // network_had_event should register an entry in burns
      burns.get_mut(&network).unwrap().push(OutInstructionWithBalance { balance, instruction });
    } else {
      panic!("Burn event wasn't Burn: {burn:?}");
    }
  }

  assert_eq!(HashSet::<&_>::from_iter(networks_with_event.iter()).len(), networks_with_event.len());

  for network in networks_with_event {
    let network_latest_finalized_block = if let Some(block) = batch_block.remove(&network) {
      block
    } else {
      // If it's had a batch or a burn, it must have had a block acknowledged
      serai
        .get_latest_block_for_network(hash, network)
        .await?
        .expect("network had a batch/burn yet never set a latest block")
    };

    processors
      .send(
        network,
        processor_messages::substrate::CoordinatorMessage::SubstrateBlock {
          context: SubstrateContext {
            serai_time: block.time().unwrap() / 1000,
            network_latest_finalized_block,
          },
          network,
          block: block.number(),
          burns: burns.remove(&network).unwrap(),
          batches: batches.remove(&network).unwrap(),
        },
      )
      .await;
  }

  Ok(())
}

// Handle a specific Substrate block, returning an error when it fails to get data
// (not blocking / holding)
#[allow(clippy::needless_pass_by_ref_mut)] // False positive?
async fn handle_block<D: Db, CNT: Clone + Fn(&mut D, TributarySpec), Pro: Processors>(
  db: &mut SubstrateDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  create_new_tributary: CNT,
  processors: &Pro,
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
    let ValidatorSetsEvent::NewSet { set } = new_set else {
      panic!("NewSet event wasn't NewSet: {new_set:?}");
    };

    // If this is Serai, do nothing
    // We only coordinate/process external networks
    if set.network == NetworkId::Serai {
      continue;
    }

    if !SubstrateDb::<D>::handled_event(&db.0, hash, event_id) {
      log::info!("found fresh new set event {:?}", new_set);
      handle_new_set(&mut db.0, key, create_new_tributary.clone(), serai, &block, set).await?;
      let mut txn = db.0.txn();
      SubstrateDb::<D>::handle_event(&mut txn, hash, event_id);
      txn.commit();
    }
    event_id += 1;
  }

  // If a key pair was confirmed, inform the processor
  for key_gen in serai.get_key_gen_events(hash).await? {
    if !SubstrateDb::<D>::handled_event(&db.0, hash, event_id) {
      log::info!("found fresh key gen event {:?}", key_gen);
      if let ValidatorSetsEvent::KeyGen { set, key_pair } = key_gen {
        // Immediately ensure this key pair is accessible to the tributary, before we fire any
        // events off of it
        let mut txn = db.0.txn();
        TributaryDb::<D>::set_key_pair(&mut txn, set, &key_pair);
        txn.commit();

        handle_key_gen(&mut db.0, processors, serai, &block, set, key_pair).await?;
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
    handle_batch_and_burns(&mut db.0, processors, serai, &block).await?;
  }
  let mut txn = db.0.txn();
  SubstrateDb::<D>::handle_event(&mut txn, hash, event_id);
  txn.commit();

  Ok(())
}

pub async fn handle_new_blocks<D: Db, CNT: Clone + Fn(&mut D, TributarySpec), Pro: Processors>(
  db: &mut SubstrateDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  create_new_tributary: CNT,
  processors: &Pro,
  serai: &Serai,
  next_block: &mut u64,
) -> Result<(), SeraiError> {
  // Check if there's been a new Substrate block
  let latest = serai.get_latest_block().await?;
  let latest_number = latest.number();
  if latest_number < *next_block {
    return Ok(());
  }
  let mut latest = Some(latest);

  for b in *next_block ..= latest_number {
    log::info!("found substrate block {b}");
    handle_block(
      db,
      key,
      create_new_tributary.clone(),
      processors,
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
    *next_block += 1;
    db.set_next_block(*next_block);
    log::info!("handled substrate block {b}");
  }

  Ok(())
}

pub async fn is_active_set(serai: &Serai, set: ValidatorSet) -> bool {
  // TODO: Track this from the Substrate scanner to reduce our overhead? We'd only have a DB
  // call, instead of a series of network requests
  let latest = loop {
    let Ok(res) = serai.get_latest_block_hash().await else {
      log::error!(
        "couldn't get the latest block hash from serai when checking tributary relevancy"
      );
      sleep(Duration::from_secs(5)).await;
      continue;
    };
    break res;
  };

  let latest_session = loop {
    let Ok(res) = serai.get_session(set.network, latest).await else {
      log::error!("couldn't get the latest session from serai when checking tributary relevancy");
      sleep(Duration::from_secs(5)).await;
      continue;
    };
    // If the on-chain Session is None, then this Session is greater and therefore, for the
    // purposes here, active
    let Some(res) = res else { return true };
    break res;
  };

  if latest_session.0 > set.session.0 {
    // If we're on the Session after the Session after this Session, then this Session is
    // definitively completed
    if latest_session.0 > (set.session.0 + 1) {
      return false;
    } else {
      // Since the next session has started, check its handover status
      let keys = loop {
        let Ok(res) = serai.get_keys(set, latest).await else {
          log::error!(
            "couldn't get the keys for a session from serai when checking tributary relevancy"
          );
          sleep(Duration::from_secs(5)).await;
          continue;
        };
        break res;
      };
      // If the keys have been deleted, then this Tributary is retired
      if keys.is_none() {
        return false;
      }
    }
  }

  true
}
