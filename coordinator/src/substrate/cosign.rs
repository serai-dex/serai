/*
  If:
    A) This block has events and it's been at least X blocks since the last cosign or
    B) This block doesn't have events but it's been X blocks since a skipped block which did
       have events or
    C) This block key gens (which changes who the cosigners are)
  cosign this block.

  This creates both a minimum and maximum delay of X blocks before a block's cosigning begins,
  barring key gens which are exceptional. The minimum delay is there to ensure we don't constantly
  spawn new protocols every 6 seconds, overwriting the old ones. The maximum delay is there to
  ensure any block needing cosigned is consigned within a reasonable amount of time.
*/

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

use serai_db::*;

use processor_messages::SubstrateContext;

use tokio::{sync::mpsc, time::sleep};

use crate::{
  Db,
  processors::Processors,
  tributary::{TributarySpec, SeraiBlockNumber},
};

// 5 minutes, expressed in blocks
// TODO: Pull a constant for block time
const COSIGN_DISTANCE: u64 = 5 * 60 / 6;

create_db!(
  SubstrateCosignDb {
    CosignTriggered: () -> (),
    IntendedCosign: () -> (u64, Option<u64>),
    BlockHasEvents: (block: u64) -> u8,
    LatestCosignedBlock: () -> u64,
  }
);

impl IntendedCosign {
  pub fn set_intended_cosign(txn: &mut impl DbTxn, intended: u64) {
    Self::set(txn, &(intended, None::<u64>));
  }
  pub fn set_skipped_cosign(txn: &mut impl DbTxn, skipped: u64) {
    let (intended, prior_skipped) = Self::get(txn).unwrap();
    assert!(prior_skipped.is_none());
    Self::set(txn, &(intended, Some(skipped)));
  }
}

impl LatestCosignedBlock {
  pub fn latest_cosigned_block(getter: &impl Get) -> u64 {
    Self::get(getter).unwrap_or_default().max(1)
  }
}

db_channel! {
  SubstrateDbChannels {
    CosignTransactions: (network: NetworkId) -> (Session, u64, [u8; 32]),
  }
}

impl CosignTransactions {
  // Append a cosign transaction.
  pub fn append_cosign(txn: &mut impl DbTxn, set: ValidatorSet, number: u64, hash: [u8; 32]) {
    CosignTransactions::send(txn, set.network, &(set.session, number, hash))
  }
}

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
          .finalized_block_by_number(block)
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

/*
  Advances the cosign protocol as should be done per the latest block.

  A block is considered cosigned if:
    A) It was cosigned
    B) It's the parent of a cosigned block
    C) It immediately follows a cosigned block and has no events requiring cosigning (TODO)
*/
async fn advance_cosign_protocol(db: &mut impl Db, serai: &Serai, latest_number: u64) -> Result<(), ()> {
  let Some((last_intended_to_cosign_block, mut skipped_block)) = IntendedCosign::get(&txn) else {
    let mut txn = db.txn();
    IntendedCosign::set_intended_cosign(&mut txn, 1);
    txn.commit();
    return Ok(());
  };
}

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
  let actual_block = serai
    .finalized_block_by_number(block)
    .await?
    .expect("couldn't get block which should've been finalized");
  SeraiBlockNumber::set(&mut txn, actual_block.hash(), &block);

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
    let serai = serai.as_of(actual_block.header.parent_hash.into());

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
  LatestCosignedBlock::set(&mut txn, &has_no_cosigners.number());
} else {
  CosignTriggered::set(&mut txn, &());
  for (set, block, hash) in cosign {
    log::debug!("cosigning {block} with {:?} {:?}", set.network, set.session);
    CosignTransactions::append_cosign(&mut txn, set, block, hash);
  }
}
txn.commit();
