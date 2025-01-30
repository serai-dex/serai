use core::future::Future;
use std::{sync::Arc, collections::HashMap};

use serai_client::{
  primitives::{SeraiAddress, Amount},
  validator_sets::primitives::ExternalValidatorSet,
  Serai,
};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::*;

create_db!(
  CosignIntend {
    ScanCosignFrom: () -> u64,
  }
);

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub(crate) struct BlockEventData {
  pub(crate) block_number: u64,
  pub(crate) has_events: HasEvents,
}

db_channel! {
  CosignIntendChannels {
    GlobalSessionsChannel: () -> ([u8; 32], GlobalSession),
    BlockEvents: () -> BlockEventData,
    IntendedCosigns: (set: ExternalValidatorSet) -> CosignIntent,
  }
}

async fn block_has_events_justifying_a_cosign(
  serai: &Serai,
  block_number: u64,
) -> Result<(Block, HasEvents), String> {
  let block = serai
    .finalized_block_by_number(block_number)
    .await
    .map_err(|e| format!("{e:?}"))?
    .ok_or_else(|| "couldn't get block which should've been finalized".to_string())?;
  let serai = serai.as_of(block.hash());

  if !serai.validator_sets().key_gen_events().await.map_err(|e| format!("{e:?}"))?.is_empty() {
    return Ok((block, HasEvents::Notable));
  }

  if !serai.coins().burn_with_instruction_events().await.map_err(|e| format!("{e:?}"))?.is_empty() {
    return Ok((block, HasEvents::NonNotable));
  }

  Ok((block, HasEvents::No))
}

/// A task to determine which blocks we should intend to cosign.
pub(crate) struct CosignIntendTask<D: Db> {
  pub(crate) db: D,
  pub(crate) serai: Arc<Serai>,
}

impl<D: Db> ContinuallyRan for CosignIntendTask<D> {
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let start_block_number = ScanCosignFrom::get(&self.db).unwrap_or(1);
      let latest_block_number =
        self.serai.latest_finalized_block().await.map_err(|e| format!("{e:?}"))?.number();

      for block_number in start_block_number ..= latest_block_number {
        let mut txn = self.db.txn();

        let (block, mut has_events) =
          block_has_events_justifying_a_cosign(&self.serai, block_number)
            .await
            .map_err(|e| format!("{e:?}"))?;

        // Check we are indexing a linear chain
        if (block_number > 1) &&
          (<[u8; 32]>::from(block.header.parent_hash) !=
            SubstrateBlockHash::get(&txn, block_number - 1)
              .expect("indexing a block but haven't indexed its parent"))
        {
          Err(format!(
            "node's block #{block_number} doesn't build upon the block #{} prior indexed",
            block_number - 1
          ))?;
        }
        let block_hash = block.hash();
        SubstrateBlockHash::set(&mut txn, block_number, &block_hash);

        let global_session_for_this_block = LatestGlobalSessionIntended::get(&txn);

        // If this is notable, it creates a new global session, which we index into the database
        // now
        if has_events == HasEvents::Notable {
          let serai = self.serai.as_of(block_hash);
          let sets_and_keys = cosigning_sets(&serai).await?;
          let global_session =
            GlobalSession::id(sets_and_keys.iter().map(|(set, _key)| *set).collect());

          let mut sets = Vec::with_capacity(sets_and_keys.len());
          let mut keys = HashMap::with_capacity(sets_and_keys.len());
          let mut stakes = HashMap::with_capacity(sets_and_keys.len());
          let mut total_stake = 0;
          for (set, key) in &sets_and_keys {
            sets.push(*set);
            keys.insert(set.network, SeraiAddress::from(*key));
            let stake = serai
              .validator_sets()
              .total_allocated_stake(set.network.into())
              .await
              .map_err(|e| format!("{e:?}"))?
              .unwrap_or(Amount(0))
              .0;
            stakes.insert(set.network, stake);
            total_stake += stake;
          }
          if total_stake == 0 {
            Err(format!("cosigning sets for block #{block_number} had 0 stake in total"))?;
          }

          let global_session_info = GlobalSession {
            // This session starts cosigning after this block, as this block must be cosigned by
            // the existing validators
            start_block_number: block_number + 1,
            sets,
            keys,
            stakes,
            total_stake,
          };
          GlobalSessions::set(&mut txn, global_session, &global_session_info);
          if let Some(ending_global_session) = global_session_for_this_block {
            GlobalSessionsLastBlock::set(&mut txn, ending_global_session, &block_number);
          }
          LatestGlobalSessionIntended::set(&mut txn, &global_session);
          GlobalSessionsChannel::send(&mut txn, &(global_session, global_session_info));
        }

        // If there isn't anyone available to cosign this block, meaning it'll never be cosigned,
        // we flag it as not having any events requiring cosigning so we don't attempt to
        // sign/require a cosign for it
        if global_session_for_this_block.is_none() {
          has_events = HasEvents::No;
        }

        match has_events {
          HasEvents::Notable | HasEvents::NonNotable => {
            let global_session_for_this_block = global_session_for_this_block
              .expect("global session for this block was None but still attempting to cosign it");
            let global_session_info = GlobalSessions::get(&txn, global_session_for_this_block)
              .expect("last global session intended wasn't saved to the database");

            // Tell each set of their expectation to cosign this block
            for set in global_session_info.sets {
              log::debug!("{:?} will be cosigning block #{block_number}", set);
              IntendedCosigns::send(
                &mut txn,
                set,
                &CosignIntent {
                  global_session: global_session_for_this_block,
                  block_number,
                  block_hash,
                  notable: has_events == HasEvents::Notable,
                },
              );
            }
          }
          HasEvents::No => {}
        }

        // Populate a singular feed with every block's status for the evluator to work off of
        BlockEvents::send(&mut txn, &(BlockEventData { block_number, has_events }));
        // Mark this block as handled, meaning we should scan from the next block moving on
        ScanCosignFrom::set(&mut txn, &(block_number + 1));
        txn.commit();
      }

      Ok(start_block_number <= latest_block_number)
    }
  }
}
