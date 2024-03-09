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

use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};

use borsh::{BorshSerialize, BorshDeserialize};

use serai_client::{
  SeraiError, Serai,
  primitives::NetworkId,
  validator_sets::primitives::{Session, ValidatorSet},
};

use serai_db::*;

use crate::{Db, substrate::in_set, tributary::SeraiBlockNumber};

// 5 minutes, expressed in blocks
// TODO: Pull a constant for block time
const COSIGN_DISTANCE: u64 = 5 * 60 / 6;

#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
enum HasEvents {
  KeyGen,
  Yes,
  No,
}

create_db!(
  SubstrateCosignDb {
    ScanCosignFrom: () -> u64,
    IntendedCosign: () -> (u64, Option<u64>),
    BlockHasEvents: (block: u64) -> HasEvents,
    LatestCosignedBlock: () -> u64,
  }
);

impl IntendedCosign {
  // Sets the intended to cosign block, clearing the prior value entirely.
  pub fn set_intended_cosign(txn: &mut impl DbTxn, intended: u64) {
    Self::set(txn, &(intended, None::<u64>));
  }

  // Sets the cosign skipped since the last intended to cosign block.
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

      BlockHasEvents::set(txn, block, &has_events);
      Ok(has_events)
    }
    Some(code) => Ok(code),
  }
}

async fn potentially_cosign_block(
  txn: &mut impl DbTxn,
  serai: &Serai,
  block: u64,
  skipped_block: Option<u64>,
  window_end_exclusive: u64,
) -> Result<bool, SeraiError> {
  // The following code regarding marking cosigned if prior block is cosigned expects this block to
  // not be zero
  // While we could perform this check there, there's no reason not to optimize the entire function
  // as such
  if block == 0 {
    return Ok(false);
  }

  let block_has_events = block_has_events(txn, serai, block).await?;

  // If this block had no events and immediately follows a cosigned block, mark it as cosigned
  if (block_has_events == HasEvents::No) &&
    (LatestCosignedBlock::latest_cosigned_block(txn) == (block - 1))
  {
    LatestCosignedBlock::set(txn, &block);
  }

  // If we skipped a block, we're supposed to sign it plus the COSIGN_DISTANCE if no other blocks
  // trigger a cosigning protocol covering it
  // This means there will be the maximum delay allowed from a block needing cosigning occurring
  // and a cosign for it triggering
  let maximally_latent_cosign_block =
    skipped_block.map(|skipped_block| skipped_block + COSIGN_DISTANCE);

  // If this block is within the window,
  if block < window_end_exclusive {
    // and set a key, cosign it
    if block_has_events == HasEvents::KeyGen {
      IntendedCosign::set_intended_cosign(txn, block);
      // Carry skipped if it isn't included by cosigning this block
      if let Some(skipped) = skipped_block {
        if skipped > block {
          IntendedCosign::set_skipped_cosign(txn, block);
        }
      }
      return Ok(true);
    }
  } else if (Some(block) == maximally_latent_cosign_block) || (block_has_events != HasEvents::No) {
    // Since this block was outside the window and had events/was maximally latent, cosign it
    IntendedCosign::set_intended_cosign(txn, block);
    return Ok(true);
  }
  Ok(false)
}

/*
  Advances the cosign protocol as should be done per the latest block.

  A block is considered cosigned if:
    A) It was cosigned
    B) It's the parent of a cosigned block
    C) It immediately follows a cosigned block and has no events requiring cosigning

  This only actually performs advancement within a limited bound (generally until it finds a block
  which should be cosigned). Accordingly, it is necessary to call multiple times even if
  `latest_number` doesn't change.
*/
async fn advance_cosign_protocol_inner(
  db: &mut impl Db,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: &Serai,
  latest_number: u64,
) -> Result<(), SeraiError> {
  let mut txn = db.txn();

  const INITIAL_INTENDED_COSIGN: u64 = 1;
  let (last_intended_to_cosign_block, mut skipped_block) = {
    let intended_cosign = IntendedCosign::get(&txn);
    // If we haven't prior intended to cosign a block, set the intended cosign to 1
    if let Some(intended_cosign) = intended_cosign {
      intended_cosign
    } else {
      IntendedCosign::set_intended_cosign(&mut txn, INITIAL_INTENDED_COSIGN);
      IntendedCosign::get(&txn).unwrap()
    }
  };

  // "windows" refers to the window of blocks where even if there's a block which should be
  // cosigned, it won't be due to proximity due to the prior cosign
  let mut window_end_exclusive = last_intended_to_cosign_block + COSIGN_DISTANCE;
  // If we've never triggered a cosign, don't skip any cosigns based on proximity
  if last_intended_to_cosign_block == INITIAL_INTENDED_COSIGN {
    window_end_exclusive = 0;
  }

  // Check all blocks within the window to see if they should be cosigned
  // If so, we're skipping them and need to flag them as skipped so that once the window closes, we
  // do cosign them
  // We only perform this check if we haven't already marked a block as skipped since the cosign
  // the skipped block will cause will cosign all other blocks within this window
  if skipped_block.is_none() {
    for b in (last_intended_to_cosign_block + 1) .. window_end_exclusive.min(latest_number) {
      if block_has_events(&mut txn, serai, b).await? == HasEvents::Yes {
        skipped_block = Some(b);
        log::debug!("skipping cosigning {b} due to proximity to prior cosign");
        IntendedCosign::set_skipped_cosign(&mut txn, b);
        break;
      }
    }
  }

  // A block which should be cosigned
  let mut to_cosign = None;
  // A list of sets which are cosigning, along with a boolean of if we're in the set
  let mut cosigning = vec![];

  // The consensus rules for this are `last_intended_to_cosign_block + 1`
  let scan_start_block = last_intended_to_cosign_block + 1;
  // As a practical optimization, we don't re-scan old blocks since old blocks are independent to
  // new state
  let scan_start_block = scan_start_block.max(ScanCosignFrom::get(&txn).unwrap_or(0));
  for block in scan_start_block ..= latest_number {
    // This TX is committed, always re-run this loop from immediately before this block
    // That allows the below loop to break out on a block it wants to revisit later
    ScanCosignFrom::set(&mut txn, &(scan_start_block - 1));

    let actual_block = serai
      .finalized_block_by_number(block)
      .await?
      .expect("couldn't get block which should've been finalized");

    // Save the block number for this block, as needed by the cosigner to perform cosigning
    SeraiBlockNumber::set(&mut txn, actual_block.hash(), &block);

    if potentially_cosign_block(&mut txn, serai, block, skipped_block, window_end_exclusive).await?
    {
      to_cosign = Some((block, actual_block.hash()));

      // Get the keys as of the prior block
      // If this key sets new keys, the coordinator won't acknowledge so until we process this
      // block
      // We won't process this block until its co-signed
      // Using the keys of the prior block ensures this deadlock isn't reached
      let serai = serai.as_of(actual_block.header.parent_hash.into());

      for network in serai_client::primitives::NETWORKS {
        // Get the latest session to have set keys
        let set_with_keys = {
          let Some(latest_session) = serai.validator_sets().session(network).await? else {
            continue;
          };
          let prior_session = Session(latest_session.0.saturating_sub(1));
          if serai
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
          }
        };

        log::debug!("{:?} will be cosigning {block}", set_with_keys.network);
        cosigning.push((set_with_keys, in_set(key, &serai, set_with_keys).await?.unwrap()));
      }

      break;
    }
  }

  if let Some((number, hash)) = to_cosign {
    // If this block doesn't have cosigners, yet does have events, automatically mark it as
    // cosigned
    if cosigning.is_empty() {
      log::debug!("{} had no cosigners available, marking as cosigned", number);
      LatestCosignedBlock::set(&mut txn, &number);
    } else {
      for (set, in_set) in cosigning {
        if in_set {
          log::debug!("cosigning {number} with {:?} {:?}", set.network, set.session);
          CosignTransactions::append_cosign(&mut txn, set, number, hash);
        }
      }
    }
  }
  txn.commit();

  Ok(())
}

pub async fn advance_cosign_protocol(
  db: &mut impl Db,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: &Serai,
  latest_number: u64,
) -> Result<(), SeraiError> {
  loop {
    let scan_from = ScanCosignFrom::get(db).unwrap_or(0);
    // Only scan 1000 blocks at a time to limit a massive txn from forming
    let scan_to = latest_number.min(scan_from + 1000);
    advance_cosign_protocol_inner(db, key, serai, scan_to).await?;
    // If we didn't limit the scan_to, break
    if scan_to == latest_number {
      break;
    }
  }
  Ok(())
}
