use std::collections::HashMap;

use zeroize::Zeroizing;

use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use serai_client::{SeraiError, Block, Serai, validator_sets::ValidatorSetsEvent};

use tributary::Tributary;

use crate::{Db, MainDb, TributaryTransaction, P2p};

async fn handle_block<D: Db, P: P2p>(
  db: &mut MainDb<D>,
  p2p: &P,
  serai: &Serai,
  block: Block,
) -> Result<(), SeraiError> {
  let hash = block.hash();

  let mut event_id = 0;

  // If a new validator set was activated, create tributary/inform processor to do a DKG
  for new_set in serai.get_new_set_events(hash).await? {
    if !db.handled_event(hash, event_id) {
      if let ValidatorSetsEvent::NewSet { set } = new_set {
        let set_data = serai.get_validator_set(set).await?.unwrap();

        let mut genesis = RecommendedTranscript::new(b"Serai Tributary Genesis");
        genesis.append_message(b"serai_block", hash);
        genesis.append_message(b"session", set.session.0.to_le_bytes());
        genesis.append_message(b"network", set.network.0.to_le_bytes());
        let genesis = genesis.challenge(b"genesis");
        let genesis_ref: &[u8] = genesis.as_ref();
        let genesis = genesis_ref[.. 32].try_into().unwrap();

        let mut validators = HashMap::new();
        for (participant, amount) in &set_data.participants {
          validators.insert(
            // TODO2: Ensure an invalid public key can't be a validator
            <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut participant.0.as_ref()).unwrap(),
            // Give one weight on Tributary per bond instance
            amount.0 / set_data.bond.0,
          );
        }

        // TODO: Do something with this
        let tributary = Tributary::<_, TributaryTransaction, _>::new(
          // TODO2: Use a DB on a dedicated volume
          db.0.clone(),
          genesis,
          block.time().unwrap(),
          Zeroizing::new(<Ristretto as Ciphersuite>::F::ZERO), // TODO
          validators,
          p2p.clone(),
        )
        .await
        .unwrap();
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
      // TODO: Handle key_gen
      db.handle_event(hash, event_id);
    }
    event_id += 1;
  }

  // If batch, tell processor of block acknowledged/burns
  for batch in serai.get_batch_events(hash).await? {
    if !db.handled_event(hash, event_id) {
      // TODO: Handle batch
      db.handle_event(hash, event_id);
    }
    event_id += 1;
  }

  Ok(())
}

pub async fn handle_new_blocks<D: Db, P: P2p>(
  db: &mut MainDb<D>,
  p2p: &P,
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
      p2p,
      serai,
      if b == latest_number {
        latest.take().unwrap()
      } else {
        serai.get_block_by_number(b).await?.unwrap()
      },
    )
    .await?;
    // TODO: Update the DB
    *last_substrate_block += 1;
  }

  Ok(())
}
