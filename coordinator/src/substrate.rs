use core::{time::Duration, ops::Deref};
use std::collections::HashMap;

use zeroize::Zeroizing;

use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use frost::{Participant, ThresholdParams};

use tokio::time::sleep;

use serai_client::{
  SeraiError, Block, Serai,
  primitives::BlockHash,
  validator_sets::{
    primitives::{Session, ValidatorSet, ValidatorSetData},
    ValidatorSetsEvent,
  },
  in_instructions::InInstructionsEvent,
  tokens::{primitives::OutInstructionWithBalance, TokensEvent},
};

use tributary::Tributary;

use processor_messages::{SubstrateContext, key_gen::KeyGenId};

use crate::{Db, MainDb, TributaryTransaction, P2p};

async fn get_set(serai: &Serai, set: ValidatorSet) -> ValidatorSetData {
  loop {
    match serai.get_validator_set(set).await {
      Ok(data) => return data.unwrap(),
      Err(e) => {
        log::error!("couldn't get validator set data: {e}");
        sleep(Duration::from_secs(5)).await;
      }
    }
  }
}

async fn get_coin_keys(serai: &Serai, set: ValidatorSet) -> Vec<u8> {
  loop {
    match serai.get_keys(set).await {
      Ok(data) => return data.unwrap().1.into_inner(),
      Err(e) => {
        log::error!("couldn't get validator set's keys: {e}");
        sleep(Duration::from_secs(5)).await;
      }
    }
  }
}

async fn in_set(
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: &Serai,
  set: ValidatorSet,
) -> bool {
  let data = get_set(serai, set).await;
  let key = Ristretto::generator() * key.deref();
  data.participants.iter().any(|(participant, _)| participant.0 == key.to_bytes())
}

async fn handle_block<D: Db, P: P2p>(
  db: &mut MainDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
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

        let mut i = None;
        let mut validators = HashMap::new();
        for (l, (participant, amount)) in set_data.participants.iter().enumerate() {
          // TODO2: Ensure an invalid public key can't be a validator
          let participant =
            <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut participant.0.as_ref()).unwrap();
          if participant == (Ristretto::generator() * key.deref()) {
            i = Some(Participant::new((l + 1).try_into().unwrap()).unwrap());
          }

          // Give one weight on Tributary per bond instance
          validators.insert(participant, amount.0 / set_data.bond.0);
        }

        if let Some(i) = i {
          let n = u16::try_from(set_data.participants.len()).unwrap();
          let t = (2 * (n / 3)) + 1;

          let mut genesis = RecommendedTranscript::new(b"Serai Tributary Genesis");
          genesis.append_message(b"serai_block", hash);
          genesis.append_message(b"session", set.session.0.to_le_bytes());
          genesis.append_message(b"network", set.network.0.to_le_bytes());
          let genesis = genesis.challenge(b"genesis");
          let genesis_ref: &[u8] = genesis.as_ref();
          let genesis = genesis_ref[.. 32].try_into().unwrap();

          // TODO: Do something with this
          let tributary = Tributary::<_, TributaryTransaction, _>::new(
            // TODO2: Use a DB on a dedicated volume
            db.0.clone(),
            genesis,
            block.time().unwrap(),
            key.clone(),
            validators,
            p2p.clone(),
          )
          .await
          .unwrap();

          // Trigger a DKG
          // TODO: Send this to processor. Check how it handles it being fired multiple times
          let msg = processor_messages::key_gen::CoordinatorMessage::GenerateKey {
            id: KeyGenId { set, attempt: 0 },
            params: ThresholdParams::new(t, n, i).unwrap(),
          };
        }
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
        if in_set(key, serai, set).await {
          // TODO: Send this to processor. Check how it handles it being fired multiple times
          let msg = processor_messages::key_gen::CoordinatorMessage::ConfirmKeyPair {
            context: SubstrateContext {
              coin_latest_finalized_block: serai
                .get_latest_block_for_network(hash, set.network)
                .await?
                .unwrap_or(BlockHash([0; 32])), // TODO: Have the processor override this
            },
            id: KeyGenId { set, attempt: todo!() },
          };
        }
      } else {
        panic!("KeyGen event wasn't KeyGen: {key_gen:?}");
      }
      db.handle_event(hash, event_id);
    }
    event_id += 1;
  }

  if !db.handled_event(hash, event_id) {
    // Finally, tell the processor of acknowledged blocks/burns
    let mut coins_with_event = vec![];
    let mut batch_block = HashMap::new();
    let mut burns = HashMap::new();

    for batch in serai.get_batch_events(hash).await? {
      if let InInstructionsEvent::Batch { network, id: _, block: coin_block } = batch {
        // Don't insert this multiple times, yet use a Vec to maintain the insertion order
        if !coins_with_event.contains(&network) {
          coins_with_event.push(network);
          burns.insert(network, vec![]);
        }

        // Use the last specified block
        batch_block.insert(network, coin_block);

        // TODO: Send this to processor. Check how it handles it being fired multiple times
        let msg = processor_messages::coordinator::CoordinatorMessage::BatchSigned {
          key: get_coin_keys(serai, ValidatorSet { network, session: Session(0) }).await, // TODO2
          block: coin_block,
        };
      } else {
        panic!("Batch event wasn't Batch: {batch:?}");
      }
    }

    for burn in serai.get_burn_events(hash).await? {
      if let TokensEvent::Burn { address: _, balance, instruction } = burn {
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

        if !coins_with_event.contains(&network) {
          coins_with_event.push(network);
          burns.insert(network, vec![]);
        }

        let mut burns_so_far = burns.remove(&network).unwrap_or(vec![]);
        burns_so_far.push(OutInstructionWithBalance { balance, instruction });
        burns.insert(network, burns_so_far);
      } else {
        panic!("Burn event wasn't Burn: {burn:?}");
      }
    }

    for network in coins_with_event {
      let coin_latest_finalized_block = if let Some(block) = batch_block.remove(&network) {
        block
      } else {
        // If it's had a batch or a burn, it must have had a block acknowledged
        serai.get_latest_block_for_network(hash, network).await?.unwrap()
      };

      // TODO: Send this to processor. Check how it handles it being fired multiple times
      let msg = processor_messages::substrate::CoordinatorMessage::SubstrateBlock {
        context: SubstrateContext { coin_latest_finalized_block },
        key: get_coin_keys(serai, ValidatorSet { network, session: Session(0) }).await, // TODO2
        // Use remove not only to avoid a clone, yet so if network is present twice somehow, this
        // isn't fired multiple times
        burns: burns.remove(&network).unwrap(),
      };
    }
  }
  db.handle_event(hash, event_id);

  Ok(())
}

pub async fn handle_new_blocks<D: Db, P: P2p>(
  db: &mut MainDb<D>,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
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
      key,
      p2p,
      serai,
      if b == latest_number {
        latest.take().unwrap()
      } else {
        serai.get_block_by_number(b).await?.unwrap()
      },
    )
    .await?;
    *last_substrate_block += 1;
    db.set_last_substrate_block(*last_substrate_block);
  }

  Ok(())
}
