use core::{ops::Deref, time::Duration};
use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
};

use zeroize::Zeroizing;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use scale::{Encode, Decode};
use serai_client::{
  SeraiError, Block, Serai, TemporalSerai,
  primitives::{BlockHash, NetworkId},
  validator_sets::{
    primitives::{Session, ValidatorSet, KeyPair, amortize_excess_key_shares},
    ValidatorSetsEvent,
  },
  in_instructions::InInstructionsEvent,
  coins::CoinsEvent,
};

use serai_db::DbTxn;

use processor_messages::SubstrateContext;

use futures::stream::StreamExt;
use tokio::{sync::mpsc, time::sleep};

use crate::{
  Db,
  processors::Processors,
  tributary::{TributarySpec, SeraiBlockNumber, TributaryDb},
};

mod db;
pub use db::*;

async fn in_set(
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: &TemporalSerai<'_>,
  set: ValidatorSet,
) -> Result<Option<bool>, SeraiError> {
  let Some(participants) = serai.validator_sets().participants(set.network).await? else {
    return Ok(None);
  };
  let key = (Ristretto::generator() * key.deref()).to_bytes();
  Ok(Some(participants.iter().any(|participant| participant.0 == key)))
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
      let serai = serai.as_of(block.hash()).validator_sets();
      let set_participants =
        serai.participants(set.network).await?.expect("NewSet for set which doesn't exist");

      let allocation_per_key_share = serai
        .allocation_per_key_share(set.network)
        .await?
        .expect("NewSet for set which didn't have an allocation per key share")
        .0;

      let mut set_data = vec![];
      for participant in set_participants {
        let allocation = serai
          .allocation(set.network, participant)
          .await?
          .expect("validator selected for set yet didn't have an allocation")
          .0;
        set_data.push((participant, u16::try_from(allocation / allocation_per_key_share).unwrap()));
      }
      amortize_excess_key_shares(&mut set_data);
      set_data
    };

    let time = if let Ok(time) = block.time() {
      time
    } else {
      assert_eq!(block.number(), 0);
      // Use the next block's time
      loop {
        let Ok(Some(res)) = serai.block_by_number(1).await else {
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
    crate::MainDb::<D>::add_participating_in_tributary(txn, &spec);

    new_tributary_spec.send(spec).unwrap();
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
            .as_of(block.hash())
            .in_instructions()
            .latest_block_for_network(set.network)
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
async fn handle_block<D: Db, Pro: Processors>(
  db: &mut SubstrateDb<D>,
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
      let mut txn = db.0.txn();
      handle_new_set::<D>(&mut txn, key, new_tributary_spec, serai, &block, set).await?;
      SubstrateDb::<D>::handle_event(&mut txn, hash, event_id);
      txn.commit();
    }
    event_id += 1;
  }

  // If a key pair was confirmed, inform the processor
  for key_gen in serai.as_of(hash).validator_sets().key_gen_events().await? {
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

  for retired_set in serai.as_of(hash).validator_sets().set_retired_events().await? {
    let ValidatorSetsEvent::SetRetired { set } = retired_set else {
      panic!("SetRetired event wasn't SetRetired: {retired_set:?}");
    };

    if set.network == NetworkId::Serai {
      continue;
    }

    if !SubstrateDb::<D>::handled_event(&db.0, hash, event_id) {
      log::info!("found fresh set retired event {:?}", retired_set);
      let mut txn = db.0.txn();
      crate::MainDb::<D>::retire_tributary(&mut txn, set);
      tributary_retired.send(set).unwrap();
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

async fn handle_new_blocks<D: Db, Pro: Processors>(
  db: &mut SubstrateDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  new_tributary_spec: &mpsc::UnboundedSender<TributarySpec>,
  tributary_retired: &mpsc::UnboundedSender<ValidatorSet>,
  processors: &Pro,
  serai: &Serai,
  next_block: &mut u64,
) -> Result<(), SeraiError> {
  // Check if there's been a new Substrate block
  let latest_number = serai.latest_block().await?.number();

  // TODO: If this block directly builds off a cosigned block *and* doesn't contain events, mark
  // cosigned,
  // TODO: Can we remove any of these events while maintaining security?
  {
    // If:
    //   A) This block has events and it's been at least X blocks since the last cosign or
    //   B) This block doesn't have events but it's been X blocks since a skipped block which did
    //      have events or
    //   C) This block key gens (which changes who the cosigners are)
    // cosign this block.
    const COSIGN_DISTANCE: u64 = 5 * 60 / 6; // 5 minutes, expressed in blocks

    #[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode)]
    enum HasEvents {
      KeyGen,
      Yes,
      No,
    }
    async fn block_has_events(
      txn: &mut impl DbTxn,
      serai: &Serai,
      block: u64,
    ) -> Result<HasEvents, SeraiError> {
      let cached = BlockHasEvents::get(txn, block);
      match cached {
        None => {
          let serai = serai.as_of(
            serai
              .block_by_number(block)
              .await?
              .expect("couldn't get block which should've been finalized")
              .hash(),
          );

          if !serai.validator_sets().key_gen_events().await?.is_empty() {
            return Ok(HasEvents::KeyGen);
          }

          let has_no_events = serai.coins().burn_with_instruction_events().await?.is_empty() &&
            serai.in_instructions().batch_events().await?.is_empty() &&
            serai.validator_sets().new_set_events().await?.is_empty() &&
            serai.validator_sets().set_retired_events().await?.is_empty();

          let has_events = if has_no_events { HasEvents::No } else { HasEvents::Yes };

          let has_events = has_events.encode();
          assert_eq!(has_events.len(), 1);
          BlockHasEvents::set(txn, block, &has_events[0]);
          Ok(HasEvents::Yes)
        }
        Some(code) => Ok(HasEvents::decode(&mut [code].as_slice()).unwrap()),
      }
    }

    let mut txn = db.0.txn();
    let Some((last_intended_to_cosign_block, mut skipped_block)) = IntendedCosign::get(&txn) else {
      IntendedCosign::set_intended_cosign(&mut txn, 1);
      txn.commit();
      return Ok(());
    };

    // If we haven't flagged skipped, and a block within the distance had events, flag the first
    // such block as skipped
    let mut distance_end_exclusive = last_intended_to_cosign_block + COSIGN_DISTANCE;
    // If we've never triggered a cosign, don't skip any cosigns
    if CosignTriggered::get(&txn).is_none() {
      distance_end_exclusive = 0;
    }
    if skipped_block.is_none() {
      for b in (last_intended_to_cosign_block + 1) .. distance_end_exclusive {
        if b > latest_number {
          break;
        }

        if block_has_events(&mut txn, serai, b).await? == HasEvents::Yes {
          skipped_block = Some(b);
          log::debug!("skipping cosigning {b} due to proximity to prior cosign");
          IntendedCosign::set_skipped_cosign(&mut txn, b);
          break;
        }
      }
    }

    let mut has_no_cosigners = None;
    let mut cosign = vec![];

    // Block we should cosign no matter what if no prior blocks qualified for cosigning
    let maximally_latent_cosign_block =
      skipped_block.map(|skipped_block| skipped_block + COSIGN_DISTANCE);
    for block in (last_intended_to_cosign_block + 1) ..= latest_number {
      SeraiBlockNumber::set(
        &mut txn,
        serai
          .block_by_number(block)
          .await?
          .expect("couldn't get block which should've been finalized")
          .hash(),
        &block,
      );

      let mut set = false;

      let block_has_events = block_has_events(&mut txn, serai, block).await?;
      // If this block is within the distance,
      if block < distance_end_exclusive {
        // and set a key, cosign it
        if block_has_events == HasEvents::KeyGen {
          IntendedCosign::set_intended_cosign(&mut txn, block);
          set = true;
          // Carry skipped if it isn't included by cosigning this block
          if let Some(skipped) = skipped_block {
            if skipped > block {
              IntendedCosign::set_skipped_cosign(&mut txn, block);
            }
          }
        }
      } else if (Some(block) == maximally_latent_cosign_block) ||
        (block_has_events != HasEvents::No)
      {
        // Since this block was outside the distance and had events/was maximally latent, cosign it
        IntendedCosign::set_intended_cosign(&mut txn, block);
        set = true;
      }

      if set {
        // Get the keys as of the prior block
        // That means if this block is setting new keys (which won't lock in until we process this
        // block), we won't freeze up waiting for the yet-to-be-processed keys to sign this block
        let actual_block = serai
          .block_by_number(block)
          .await?
          .expect("couldn't get block which should've been finalized");
        let serai = serai.as_of(actual_block.header().parent_hash.into());

        has_no_cosigners = Some(actual_block.clone());

        for network in serai_client::primitives::NETWORKS {
          // Get the latest session to have set keys
          let Some(latest_session) = serai.validator_sets().session(network).await? else {
            continue;
          };
          let prior_session = Session(latest_session.0.saturating_sub(1));
          let set_with_keys = if serai
            .validator_sets()
            .keys(ValidatorSet { network, session: prior_session })
            .await?
            .is_some()
          {
            ValidatorSet { network, session: prior_session }
          } else {
            let set = ValidatorSet { network, session: latest_session };
            if serai.validator_sets().keys(set).await?.is_none() {
              continue;
            }
            set
          };

          // Since this is a valid cosigner, don't flag this block as having no cosigners
          has_no_cosigners = None;
          log::debug!("{:?} will be cosigning {block}", set_with_keys.network);

          if in_set(key, &serai, set_with_keys).await?.unwrap() {
            cosign.push((set_with_keys, block, actual_block.hash()));
          }
        }

        break;
      }
    }

    // If this block doesn't have cosigners, yet does have events, automatically mark it as
    // cosigned
    if let Some(has_no_cosigners) = has_no_cosigners {
      log::debug!("{} had no cosigners available, marking as cosigned", has_no_cosigners.number());
      SubstrateDb::<D>::set_latest_cosigned_block(&mut txn, has_no_cosigners.number());
      txn.commit();
    } else {
      CosignTriggered::set(&mut txn, &());
      let mut txn = CosignTxn::new(txn);
      for (set, block, hash) in cosign {
        log::debug!("cosigning {block} with {:?} {:?}", set.network, set.session);
        CosignTransactions::append_cosign(&mut txn, set, block, hash);
      }
      txn.commit();
    }
  }

  // Reduce to the latest cosigned block
  let latest_number = latest_number.min(SubstrateDb::<D>::latest_cosigned_block(&db.0));

  if latest_number < *next_block {
    return Ok(());
  }

  for b in *next_block ..= latest_number {
    log::info!("found substrate block {b}");
    handle_block(
      db,
      key,
      new_tributary_spec,
      tributary_retired,
      processors,
      serai,
      serai
        .block_by_number(b)
        .await?
        .expect("couldn't get block before the latest finalized block"),
    )
    .await?;
    *next_block += 1;
    db.set_next_block(*next_block);
    log::info!("handled substrate block {b}");
  }

  Ok(())
}

pub async fn scan_task<D: Db, Pro: Processors>(
  db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  processors: Pro,
  serai: Arc<Serai>,
  new_tributary_spec: mpsc::UnboundedSender<TributarySpec>,
  tributary_retired: mpsc::UnboundedSender<ValidatorSet>,
) {
  log::info!("scanning substrate");

  let mut db = SubstrateDb::new(db);
  let mut next_substrate_block = db.next_block();

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
  let mut substrate_block_notifier = new_substrate_block_notifier().await;

  loop {
    // await the next block, yet if our notifier had an error, re-create it
    {
      let Ok(next_block) =
        tokio::time::timeout(Duration::from_secs(60), substrate_block_notifier.next()).await
      else {
        // Timed out, which may be because Serai isn't finalizing or may be some issue with the
        // notifier
        if serai.latest_block().await.map(|block| block.number()).ok() ==
          Some(next_substrate_block.saturating_sub(1))
        {
          log::info!("serai hasn't finalized a block in the last 60s...");
        } else {
          substrate_block_notifier = new_substrate_block_notifier().await;
        }
        continue;
      };

      // next_block is a Option<Result>
      if next_block.and_then(Result::ok).is_none() {
        substrate_block_notifier = new_substrate_block_notifier().await;
        continue;
      }
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
pub(crate) async fn get_expected_next_batch(serai: &Serai, network: NetworkId) -> u32 {
  let mut first = true;
  loop {
    if !first {
      log::error!("{} {network:?}", "couldn't connect to Serai node to get the next batch ID for",);
      sleep(Duration::from_secs(5)).await;
    }
    first = false;

    let Ok(latest_block) = serai.latest_block().await else {
      continue;
    };
    let Ok(last) =
      serai.as_of(latest_block.hash()).in_instructions().last_batch_for_network(network).await
    else {
      continue;
    };
    break if let Some(last) = last { last + 1 } else { 0 };
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
  let last = crate::MainDb::<D>::last_verified_batch(txn, network);
  for id in last.map(|last| last + 1).unwrap_or(0) ..= optimistic_up_to {
    let Some(on_chain) = SubstrateDb::<D>::batch_instructions_hash(txn, network, id) else {
      break;
    };
    let off_chain = crate::MainDb::<D>::expected_batch(txn, network, id).unwrap();
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
    crate::MainDb::<D>::save_last_verified_batch(txn, network, id);
  }

  crate::MainDb::<D>::last_verified_batch(txn, network)
}
