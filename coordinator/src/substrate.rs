use core::ops::Deref;
use std::collections::{HashSet, HashMap};

use zeroize::Zeroizing;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use frost::{Participant, ThresholdParams};

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

use tributary::Tributary;

use processor_messages::{SubstrateContext, key_gen::KeyGenId, CoordinatorMessage};

use crate::{Db, MainDb, P2p, processor::Processor};

async fn get_coin_key(serai: &Serai, set: ValidatorSet) -> Result<Option<Vec<u8>>, SeraiError> {
  Ok(serai.get_keys(set).await?.map(|keys| keys.1.into_inner()))
}

async fn in_set(
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: &Serai,
  set: ValidatorSet,
) -> Result<Option<Option<Participant>>, SeraiError> {
  let Some(data) = serai.get_validator_set(set).await? else {
    return Ok(None);
  };
  let key = (Ristretto::generator() * key.deref()).to_bytes();
  Ok(Some(
    data
      .participants
      .iter()
      .position(|(participant, _)| participant.0 == key)
      .map(|index| Participant::new((index + 1).try_into().unwrap()).unwrap()),
  ))
}

async fn handle_new_set<D: Db, Pro: Processor, P: P2p>(
  db: &mut MainDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  p2p: &P,
  processor: &mut Pro,
  serai: &Serai,
  block: &Block,
  set: ValidatorSet,
) -> Result<(), SeraiError> {
  if let Some(i) = in_set(key, serai, set).await?.expect("NewSet for set which doesn't exist") {
    let set_data = serai.get_validator_set(set).await?.expect("NewSet for set which doesn't exist");

    let n = u16::try_from(set_data.participants.len()).unwrap();
    let t = (2 * (n / 3)) + 1;

    let mut validators = HashMap::new();
    for (l, (participant, amount)) in set_data.participants.iter().enumerate() {
      // TODO: Ban invalid keys from being validators on the Serai side
      let participant = <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut participant.0.as_ref())
        .expect("invalid key registered as participant");
      // Give one weight on Tributary per bond instance
      validators.insert(participant, amount.0 / set_data.bond.0);
    }

    // TODO: Do something with this
    let tributary = Tributary::<_, crate::tributary::Transaction, _>::new(
      // TODO2: Use a DB on a dedicated volume
      db.0.clone(),
      crate::tributary::genesis(block.hash(), set),
      block.time().expect("Serai block didn't have a timestamp set"),
      key.clone(),
      validators,
      p2p.clone(),
    )
    .await
    .unwrap();

    // Trigger a DKG
    // TODO: Check how the processor handles thi being fired multiple times
    // We already have a unique event ID based on block, event index (where event index is
    // the one generated in this handle_block function)
    // We could use that on this end and the processor end?
    processor
      .send(CoordinatorMessage::KeyGen(
        processor_messages::key_gen::CoordinatorMessage::GenerateKey {
          id: KeyGenId { set, attempt: 0 },
          params: ThresholdParams::new(t, n, i).unwrap(),
        },
      ))
      .await;
  }

  Ok(())
}

async fn handle_key_gen<D: Db, Pro: Processor>(
  db: &mut MainDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  processor: &mut Pro,
  serai: &Serai,
  block: &Block,
  set: ValidatorSet,
  key_pair: KeyPair,
) -> Result<(), SeraiError> {
  if in_set(key, serai, set)
    .await?
    .expect("KeyGen occurred for a set which doesn't exist")
    .is_some()
  {
    // TODO: Check how the processor handles thi being fired multiple times
    processor
      .send(CoordinatorMessage::KeyGen(
        processor_messages::substrate::CoordinatorMessage::ConfirmKeyPair {
          context: SubstrateContext {
            coin_latest_finalized_block: serai
              .get_latest_block_for_network(block.hash(), set.network)
              .await?
              .unwrap_or(BlockHash([0; 32])), // TODO: Have the processor override this
          },
          // TODO: Check the DB for which attempt used this key pair
          id: KeyGenId { set, attempt: todo!() },
        },
      ))
      .await;
  }

  Ok(())
}

async fn handle_batch_and_burns<D: Db, Pro: Processor>(
  db: &mut MainDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
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
      batch_block.insert(network, network_block);

      // TODO: Check how the processor handles thi being fired multiple times
      processor
        .send(CoordinatorMessage::Coordinator(
          processor_messages::coordinator::CoordinatorMessage::BatchSigned {
            key: get_coin_key(
              serai,
              // TODO2
              ValidatorSet { network, session: Session(0) },
            )
            .await?
            .expect("ValidatorSet without keys signed a batch"),
            block: network_block,
          },
        ))
        .await;
    } else {
      panic!("Batch event wasn't Batch: {batch:?}");
    }
  }

  for burn in serai.get_burn_events(hash).await? {
    if let TokensEvent::Burn { address: _, balance, instruction } = burn {
      // TODO: Move Network/Coin to an enum and provide this mapping
      let network = {
        use serai_client::primitives::*;
        match balance.coin {
          BITCOIN => BITCOIN_NET_ID,
          ETHER => ETHEREUM_NET_ID,
          DAI => ETHEREUM_NET_ID,
          MONERO => MONERO_NET_ID,
          invalid => panic!("burn from unrecognized coin: {invalid:?}"),
        }
      };

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

    // TODO: Check how the processor handles thi being fired multiple times
    processor
      .send(CoordinatorMessage::Substrate(
        processor_messages::substrate::CoordinatorMessage::SubstrateBlock {
          context: SubstrateContext { coin_latest_finalized_block },
          key: get_coin_key(
            serai,
            // TODO2
            ValidatorSet { network, session: Session(0) },
          )
          .await?
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
async fn handle_block<D: Db, Pro: Processor, P: P2p>(
  db: &mut MainDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  p2p: &P,
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
    if !db.handled_event(hash, event_id) {
      if let ValidatorSetsEvent::NewSet { set } = new_set {
        handle_new_set(db, key, p2p, processor, serai, &block, set).await?;
      } else {
        panic!("NewSet event wasn't NewSet: {new_set:?}");
      }
      db.handle_event(hash, event_id);
    }
    event_id += 1;
  }

  // If a key pair was confirmed, inform the processor
  for key_gen in serai.get_key_gen_events(hash).await? {
    if !db.handled_event(hash, event_id) {
      if let ValidatorSetsEvent::KeyGen { set, key_pair } = key_gen {
        handle_key_gen(db, key, processor, serai, &block, set, key_pair).await?;
      } else {
        panic!("KeyGen event wasn't KeyGen: {key_gen:?}");
      }
      db.handle_event(hash, event_id);
    }
    event_id += 1;
  }

  // Finally, tell the processor of acknowledged blocks/burns
  // This uses a single event as. unlike prior events which individually executed code, all
  // following events share data collection
  // This does break the uniqueness of (hash, event_id) -> one event, yet
  // (network, (hash, event_id)) remains valid as a unique ID for an event
  if !db.handled_event(hash, event_id) {
    handle_batch_and_burns(db, key, processor, serai, &block).await?;
  }
  db.handle_event(hash, event_id);

  Ok(())
}

pub async fn handle_new_blocks<D: Db, Pro: Processor, P: P2p>(
  db: &mut MainDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  p2p: &P,
  processor: &mut Pro,
  serai: &Serai,
  last_substrate_block: &mut u64,
) -> Result<(), SeraiError> {
  // Check if there's been a new Substrate block
  let latest = serai.get_latest_block().await?;
  let latest_number = latest.number();
  if latest_number == *last_substrate_block {
    return Ok(());
  }
  let mut latest = Some(latest);

  for b in (*last_substrate_block + 1) ..= latest_number {
    handle_block(
      db,
      key,
      p2p,
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
    *last_substrate_block += 1;
    db.set_last_substrate_block(*last_substrate_block);
  }

  Ok(())
}
