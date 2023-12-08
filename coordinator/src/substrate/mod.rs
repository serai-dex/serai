use core::{ops::Deref, time::Duration};
use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
};

use zeroize::Zeroizing;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use serai_client::{
  SeraiError, Block, Serai, TemporalSerai,
  primitives::{BlockHash, NetworkId},
  validator_sets::{
    primitives::{ValidatorSet, KeyPair, amortize_excess_key_shares},
    ValidatorSetsEvent,
  },
  in_instructions::InInstructionsEvent,
  coins::CoinsEvent,
};

use serai_db::DbTxn;

use processor_messages::SubstrateContext;

use tokio::{sync::mpsc, time::sleep};

use crate::{
  Db,
  processors::Processors,
  tributary::{TributarySpec, SeraiBlockNumber},
};

mod db;
pub use db::*;

mod cosign;
pub use cosign::*;

async fn in_set(
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: &TemporalSerai<'_>,
  set: ValidatorSet,
) -> Result<Option<bool>, SeraiError> {
  let Some(participants) = serai.validator_sets().participants(set.network).await? else {
    return Ok(None);
  };
  let key = (Ristretto::generator() * key.deref()).to_bytes();
  Ok(Some(participants.iter().any(|(participant, _)| participant.0 == key)))
}

async fn handle_new_set<D: Db>(
  txn: &mut D::Transaction<'_>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  new_tributary_spec: &mpsc::UnboundedSender<TributarySpec>,
  serai: &Serai,
  block: &Block,
  set: ValidatorSet,
) -> Result<(), SeraiError> {
  if in_set(key, &serai.as_of(block.hash()), set)
    .await?
    .expect("NewSet for set which doesn't exist")
  {
    log::info!("present in set {:?}", set);

    let set_data = {
      let serai = serai.as_of(block.hash());
      let serai = serai.validator_sets();
      let set_participants =
        serai.participants(set.network).await?.expect("NewSet for set which doesn't exist");

      let mut set_data = set_participants
        .into_iter()
        .map(|(k, w)| (k, u16::try_from(w).unwrap()))
        .collect::<Vec<_>>();
      amortize_excess_key_shares(&mut set_data);
      set_data
    };

    let time = if let Ok(time) = block.time() {
      time
    } else {
      assert_eq!(block.number(), 0);
      // Use the next block's time
      loop {
        let Ok(Some(res)) = serai.finalized_block_by_number(1).await else {
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

    log::info!("creating new tributary for {:?}", spec.set());

    // Save it to the database now, not on the channel receiver's side, so this is safe against
    // reboots
    // If this txn finishes, and we reboot, then this'll be reloaded from active Tributaries
    // If this txn doesn't finish, this will be re-fired
    // If we waited to save to the DB, this txn may be finished, preventing re-firing, yet the
    // prior fired event may have not been received yet
    crate::ActiveTributaryDb::add_participating_in_tributary(txn, &spec);

    new_tributary_spec.send(spec).unwrap();
  } else {
    log::info!("not present in new set {:?}", set);
  }

  Ok(())
}

async fn handle_key_gen<Pro: Processors>(
  processors: &Pro,
  serai: &Serai,
  block: &Block,
  set: ValidatorSet,
  key_pair: KeyPair,
) -> Result<(), SeraiError> {
  processors
    .send(
      set.network,
      processor_messages::substrate::CoordinatorMessage::ConfirmKeyPair {
        context: SubstrateContext {
          serai_time: block.time().unwrap() / 1000,
          network_latest_finalized_block: serai
            .as_of(block.hash())
            .in_instructions()
            .latest_block_for_network(set.network)
            .await?
            // The processor treats this as a magic value which will cause it to find a network
            // block which has a time greater than or equal to the Serai time
            .unwrap_or(BlockHash([0; 32])),
        },
        session: set.session,
        key_pair,
      },
    )
    .await;

  Ok(())
}

async fn handle_batch_and_burns<Pro: Processors>(
  txn: &mut impl DbTxn,
  processors: &Pro,
  serai: &Serai,
  block: &Block,
) -> Result<(), SeraiError> {
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

  let serai = serai.as_of(block.hash());
  for batch in serai.in_instructions().batch_events().await? {
    if let InInstructionsEvent::Batch { network, id, block: network_block, instructions_hash } =
      batch
    {
      network_had_event(&mut burns, &mut batches, network);

      BatchInstructionsHashDb::set(txn, network, id, &instructions_hash);

      // Make sure this is the only Batch event for this network in this Block
      assert!(batch_block.insert(network, network_block).is_none());

      // Add the batch included by this block
      batches.get_mut(&network).unwrap().push(id);
    } else {
      panic!("Batch event wasn't Batch: {batch:?}");
    }
  }

  for burn in serai.coins().burn_with_instruction_events().await? {
    if let CoinsEvent::BurnWithInstruction { from: _, instruction } = burn {
      let network = instruction.balance.coin.network();
      network_had_event(&mut burns, &mut batches, network);

      // network_had_event should register an entry in burns
      burns.get_mut(&network).unwrap().push(instruction);
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
        .in_instructions()
        .latest_block_for_network(network)
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
async fn handle_block<D: Db, Pro: Processors>(
  db: &mut D,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  new_tributary_spec: &mpsc::UnboundedSender<TributarySpec>,
  tributary_retired: &mpsc::UnboundedSender<ValidatorSet>,
  processors: &Pro,
  serai: &Serai,
  block: Block,
) -> Result<(), SeraiError> {
  let hash = block.hash();

  // Define an indexed event ID.
  let mut event_id = 0;

  // If a new validator set was activated, create tributary/inform processor to do a DKG
  for new_set in serai.as_of(hash).validator_sets().new_set_events().await? {
    // Individually mark each event as handled so on reboot, we minimize duplicates
    // Additionally, if the Serai connection also fails 1/100 times, this means a block with 1000
    // events will successfully be incrementally handled
    // (though the Serai connection should be stable, making this unnecessary)
    let ValidatorSetsEvent::NewSet { set } = new_set else {
      panic!("NewSet event wasn't NewSet: {new_set:?}");
    };

    // If this is Serai, do nothing
    // We only coordinate/process external networks
    if set.network == NetworkId::Serai {
      continue;
    }

    if EventDb::is_unhandled(db, &hash, event_id) {
      log::info!("found fresh new set event {:?}", new_set);
      let mut txn = db.txn();
      handle_new_set::<D>(&mut txn, key, new_tributary_spec, serai, &block, set).await?;
      EventDb::handle_event(&mut txn, &hash, event_id);
      txn.commit();
    }
    event_id += 1;
  }

  // If a key pair was confirmed, inform the processor
  for key_gen in serai.as_of(hash).validator_sets().key_gen_events().await? {
    if EventDb::is_unhandled(db, &hash, event_id) {
      log::info!("found fresh key gen event {:?}", key_gen);
      if let ValidatorSetsEvent::KeyGen { set, key_pair } = key_gen {
        handle_key_gen(processors, serai, &block, set, key_pair).await?;
      } else {
        panic!("KeyGen event wasn't KeyGen: {key_gen:?}");
      }
      let mut txn = db.txn();
      EventDb::handle_event(&mut txn, &hash, event_id);
      txn.commit();
    }
    event_id += 1;
  }

  for retired_set in serai.as_of(hash).validator_sets().set_retired_events().await? {
    let ValidatorSetsEvent::SetRetired { set } = retired_set else {
      panic!("SetRetired event wasn't SetRetired: {retired_set:?}");
    };

    if set.network == NetworkId::Serai {
      continue;
    }

    if EventDb::is_unhandled(db, &hash, event_id) {
      log::info!("found fresh set retired event {:?}", retired_set);
      let mut txn = db.txn();
      crate::ActiveTributaryDb::retire_tributary(&mut txn, set);
      tributary_retired.send(set).unwrap();
      EventDb::handle_event(&mut txn, &hash, event_id);
      txn.commit();
    }
    event_id += 1;
  }

  // Finally, tell the processor of acknowledged blocks/burns
  // This uses a single event as unlike prior events which individually executed code, all
  // following events share data collection
  if EventDb::is_unhandled(db, &hash, event_id) {
    let mut txn = db.txn();
    handle_batch_and_burns(&mut txn, processors, serai, &block).await?;
    EventDb::handle_event(&mut txn, &hash, event_id);
    txn.commit();
  }

  Ok(())
}

async fn handle_new_blocks<D: Db, Pro: Processors>(
  db: &mut D,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  new_tributary_spec: &mpsc::UnboundedSender<TributarySpec>,
  tributary_retired: &mpsc::UnboundedSender<ValidatorSet>,
  processors: &Pro,
  serai: &Serai,
  next_block: &mut u64,
) -> Result<(), SeraiError> {
  // Check if there's been a new Substrate block
  let latest_number = serai.latest_finalized_block().await?.number();

  // Advance the cosigning protocol
  advance_cosign_protocol(db, key, serai, latest_number).await?;

  // Reduce to the latest cosigned block
  let latest_number = latest_number.min(LatestCosignedBlock::latest_cosigned_block(db));

  if latest_number < *next_block {
    return Ok(());
  }

  for b in *next_block ..= latest_number {
    let block = serai
      .finalized_block_by_number(b)
      .await?
      .expect("couldn't get block before the latest finalized block");

    // Save the block number for this block, as needed by the Tributary code
    // TODO: Review why this is?
    let mut txn = db.txn();
    SeraiBlockNumber::set(&mut txn, block.hash(), &b);
    txn.commit();

    log::info!("handling substrate block {b}");
    handle_block(db, key, new_tributary_spec, tributary_retired, processors, serai, block).await?;
    *next_block += 1;

    let mut txn = db.txn();
    NextBlock::set(&mut txn, next_block);
    txn.commit();

    log::info!("handled substrate block {b}");
  }

  Ok(())
}

pub async fn scan_task<D: Db, Pro: Processors>(
  mut db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  processors: Pro,
  serai: Arc<Serai>,
  new_tributary_spec: mpsc::UnboundedSender<TributarySpec>,
  tributary_retired: mpsc::UnboundedSender<ValidatorSet>,
) {
  log::info!("scanning substrate");
  let mut next_substrate_block = NextBlock::get(&db).unwrap_or_default();

  /*
  let new_substrate_block_notifier = {
    let serai = &serai;
    move || async move {
      loop {
        match serai.newly_finalized_block().await {
          Ok(sub) => return sub,
          Err(e) => {
            log::error!("couldn't communicate with serai node: {e}");
            sleep(Duration::from_secs(5)).await;
          }
        }
      }
    }
  };
  */
  // TODO: Restore the above subscription-based system
  // That would require moving serai-client from HTTP to websockets
  let new_substrate_block_notifier = {
    let serai = &serai;
    move |next_substrate_block| async move {
      loop {
        match serai.latest_finalized_block().await {
          Ok(latest) => {
            if latest.header.number >= next_substrate_block {
              return latest;
            } else {
              sleep(Duration::from_secs(3)).await;
            }
          }
          Err(e) => {
            log::error!("couldn't communicate with serai node: {e}");
            sleep(Duration::from_secs(5)).await;
          }
        }
      }
    }
  };

  loop {
    // await the next block, yet if our notifier had an error, re-create it
    {
      let Ok(_) = tokio::time::timeout(
        Duration::from_secs(60),
        new_substrate_block_notifier(next_substrate_block),
      )
      .await
      else {
        // Timed out, which may be because Serai isn't finalizing or may be some issue with the
        // notifier
        if serai.latest_finalized_block().await.map(|block| block.number()).ok() ==
          Some(next_substrate_block.saturating_sub(1))
        {
          log::info!("serai hasn't finalized a block in the last 60s...");
        }
        continue;
      };

      /*
      // next_block is a Option<Result>
      if next_block.and_then(Result::ok).is_none() {
        substrate_block_notifier = new_substrate_block_notifier(next_substrate_block);
        continue;
      }
      */
    }

    match handle_new_blocks(
      &mut db,
      &key,
      &new_tributary_spec,
      &tributary_retired,
      &processors,
      &serai,
      &mut next_substrate_block,
    )
    .await
    {
      Ok(()) => {}
      Err(e) => {
        log::error!("couldn't communicate with serai node: {e}");
        sleep(Duration::from_secs(5)).await;
      }
    }
  }
}

/// Gets the expected ID for the next Batch.
///
/// Will log an error and apply a slight sleep on error, letting the caller simply immediately
/// retry.
pub(crate) async fn expected_next_batch(
  serai: &Serai,
  network: NetworkId,
) -> Result<u32, SeraiError> {
  async fn expected_next_batch_inner(serai: &Serai, network: NetworkId) -> Result<u32, SeraiError> {
    let serai = serai.as_of_latest_finalized_block().await?;
    let last = serai.in_instructions().last_batch_for_network(network).await?;
    Ok(if let Some(last) = last { last + 1 } else { 0 })
  }
  match expected_next_batch_inner(serai, network).await {
    Ok(next) => Ok(next),
    Err(e) => {
      log::error!("couldn't get the expected next batch from substrate: {e:?}");
      sleep(Duration::from_millis(100)).await;
      Err(e)
    }
  }
}

/// Verifies `Batch`s which have already been indexed from Substrate.
///
/// Spins if a distinct `Batch` is detected on-chain.
///
/// This has a slight malleability in that doesn't verify *who* published a `Batch` is as expected.
/// This is deemed fine.
pub(crate) async fn verify_published_batches<D: Db>(
  txn: &mut D::Transaction<'_>,
  network: NetworkId,
  optimistic_up_to: u32,
) -> Option<u32> {
  // TODO: Localize from MainDb to SubstrateDb
  let last = crate::LastVerifiedBatchDb::get(txn, network);
  for id in last.map(|last| last + 1).unwrap_or(0) ..= optimistic_up_to {
    let Some(on_chain) = BatchInstructionsHashDb::get(txn, network, id) else {
      break;
    };
    let off_chain = crate::ExpectedBatchDb::get(txn, network, id).unwrap();
    if on_chain != off_chain {
      // Halt operations on this network and spin, as this is a critical fault
      loop {
        log::error!(
          "{}! network: {:?} id: {} off-chain: {} on-chain: {}",
          "on-chain batch doesn't match off-chain",
          network,
          id,
          hex::encode(off_chain),
          hex::encode(on_chain),
        );
        sleep(Duration::from_secs(60)).await;
      }
    }
    crate::LastVerifiedBatchDb::set(txn, network, &id);
  }

  crate::LastVerifiedBatchDb::get(txn, network)
}
