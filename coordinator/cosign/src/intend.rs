use core::future::Future;
use std::{collections::HashMap, sync::Arc};

use blake2::{Digest as _, Blake2b256};

use serai_client_serai::{
  Serai,
  abi::{
    primitives::{
      network_id::ExternalNetworkId,
      balance::Amount,
      crypto::Public,
      validator_sets::{Session, ExternalValidatorSet},
      address::SeraiAddress,
      merkle::IncrementalUnbalancedMerkleTree,
      constants::GENESIS_LIQUIDITY_PERIOD,
    },
    validator_sets::Event,
  },
};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::*;

#[derive(BorshSerialize, BorshDeserialize)]
pub(crate) struct Set {
  pub(crate) session: Session,
  pub(crate) key: Public,
  pub(crate) stake: Amount,
}

create_db!(
  CosignIntend {
    ScanCosignFrom: () -> u64,
    BuildsUpon: () -> IncrementalUnbalancedMerkleTree,
    Stakes: (network: ExternalNetworkId, validator: SeraiAddress) -> Amount,
    Validators: (set: ExternalValidatorSet) -> Vec<SeraiAddress>,
    LatestSet: (network: ExternalNetworkId) -> Set,
    GenesisTime: () -> u64,
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

/// Fetch the `ExternalValidatorSet`s, and their associated keys, used for cosigning as of this
/// block.
fn cosigning_sets(getter: &impl Get) -> Vec<(ExternalValidatorSet, Public, Amount)> {
  ExternalNetworkId::all()
    .filter_map(|network| {
      let Set { session, key, stake } = LatestSet::get(getter, network)?;
      Some((ExternalValidatorSet { network, session }, key, stake))
    })
    .collect()
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
      let start_scan_block_number = ScanCosignFrom::get(&self.db).unwrap_or(0);
      let latest_serai_block_number = self
        .serai
        .latest_finalized_block_number()
        .await
        // Ephemeral RPC Err: task to re-run and continue trying
        .map_err(|e| format!("RPC error fetching latest finalized block number: {e}"))?;

      #[cfg(not(coverage))]
      log::debug!(
        "beginning scan: start={start_scan_block_number}, latest={latest_serai_block_number}"
      );

      if latest_serai_block_number < start_scan_block_number {
        // made_progress = False
        // Return, nothing new to progress with
        return Ok(false);
      }

      let mut made_progress = false;

      for block_number in start_scan_block_number ..= latest_serai_block_number {
        let serai_block = self
          .serai
          .block_by_number(block_number)
          .await
          // Ephemeral RPC Err: task to re-run and continue trying
          .map_err(|e| format!("RPC error fetching block #{block_number}: {e}"))?
          // Ephemeral RPC Err: Block returned None even though serai reported as finalized
          // task to re-run and continue trying
          .ok_or_else(|| "couldn't get block which should've been finalized".to_owned())?;

        let serai_block_hash = serai_block.header.hash();
        let serai_block_events = self
          .serai
          .events(&serai_block_hash)
          .await
          // Ephemeral RPC Err: task to re-run and continue trying
          .map_err(|e| format!("RPC error fetching events for block #{block_number}: {e}"))?;

        #[cfg(not(coverage))]
        log::debug!("iterating over block_number={block_number}, hash={serai_block_hash:?}");

        let mut txn = self.db.txn();
        let mut builds_upon =
          BuildsUpon::get(&txn).unwrap_or(IncrementalUnbalancedMerkleTree::new());

        // Check we are indexing a linear chain
        if serai_block.header.builds_upon() !=
          builds_upon.clone().calculate(serai_client_serai::abi::BLOCK_BRANCH_TAG)
        {
          // Ephemeral RPC Err:
          // serai.block_by_number(block_number) may return a different chain history (fork)
          // but the prior indexed block was already finalized, so we MUST build upon it
          // task to re-run and continue trying until on the finalized chain
          Err(format!(
            "node's block #{block_number} doesn't build upon the block #{} prior indexed",
            block_number - 1
          ))?;
        }

        SubstrateBlockHash::set(&mut txn, block_number, &serai_block_hash);
        builds_upon.append(
          serai_client_serai::abi::BLOCK_BRANCH_TAG,
          Blake2b256::new_with_prefix([serai_client_serai::abi::BLOCK_LEAF_TAG])
            .chain_update(serai_block_hash.0)
            .finalize()
            .into(),
        );
        BuildsUpon::set(&mut txn, &builds_upon);

        let mut has_events = HasEvents::No;
        let vset_events = serai_block_events.validator_sets();

        // Update the stakes
        for event in vset_events.allocation_events() {
          let Event::Allocation { validator, network, amount } = event else {
            unreachable!("event from `allocation_events` wasn't `Event::Allocation`")
          };
          let Ok(network) = ExternalNetworkId::try_from(*network) else {
            // Not an ExternalNetworkId, possible Serai network allocation
            // safe to skip this allocation event
            continue;
          };

          let existing = Stakes::get(&txn, network, *validator).unwrap_or(Amount(0));
          let new_amount = Amount(existing.0 + amount.0);
          Stakes::set(&mut txn, network, *validator, &new_amount);
        }
        for event in vset_events.deallocation_events() {
          let Event::Deallocation { validator, network, amount, timeline: _ } = event else {
            unreachable!("event from `deallocation_events` wasn't `Event::Deallocation`")
          };
          let Ok(network) = ExternalNetworkId::try_from(*network) else {
            // Not an ExternalNetworkId, possible Serai network allocation
            // safe to skip this deallocation event
            continue;
          };

          let existing = Stakes::get(&txn, network, *validator)
            // critical panic:
            // this is a critical issue and will not be solved after re-tries,
            // missing Stakes from previous blocks will remain missing until re-indexed (if encountered)
            // halt the process
            .expect("unable to deallocate with no prior existing stake");

          Stakes::set(&mut txn, network, *validator, &Amount(existing.0 - amount.0));
        }

        // Handle decided sets
        for event in vset_events.set_decided_events() {
          let Event::SetDecided { set, validators } = event else {
            unreachable!("event from `set_decided_events` wasn't `Event::SetDecided`")
          };

          let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };

          if validators.is_empty() {
            // Maybe ephemeral: event blocks from RPC returned empty set list
            // could resolve after retry. or will get forever stuck.
            Err(format!("validator set from Event::SetDecided was empty"))?;
          }

          Validators::set(
            &mut txn,
            set,
            &validators.iter().map(|(validator, _key_shares)| *validator).collect(),
          );
        }

        // Handle declarations of the latest set
        for event in vset_events.set_keys_events() {
          let Event::SetKeys { set, key_pair } = event else {
            unreachable!("event from `set_keys_events` wasn't `Event::SetKeys`")
          };
          has_events = HasEvents::Notable;

          let validators = Validators::take(&mut txn, *set)
            // critical panic:
            // this is a critical issue and will not be solved after re-tries,
            // missing Validators from previous blocks will remain missing until re-indexed (if encountered)
            // halt the process
            .expect("set which wasn't decided set keys");

          let stake: u64 = validators
            .iter()
            .map(|v| Stakes::get(&txn, set.network, *v).unwrap_or(Amount(0)).0)
            .sum();
          LatestSet::set(
            &mut txn,
            set.network,
            &Set { session: set.session, key: key_pair.0, stake: Amount(stake) },
          );
        }

        // Handle burn with instruction events (makes block non-notable if not already notable)
        if has_events == HasEvents::No {
          if serai_block_events.coins().burn_with_instruction_events().next().is_some() {
            has_events = HasEvents::NonNotable;
          }
        }

        let global_session_for_this_block = LatestGlobalSessionIntended::get(&txn);

        // If this is notable, it creates a new global session, which we index into the database
        // now
        if has_events == HasEvents::Notable {
          let new_sets_and_keys_and_stakes = cosigning_sets(&txn);
          let new_global_session = GlobalSession::id(
            new_sets_and_keys_and_stakes.iter().map(|(set, _key, _stake)| *set).collect(),
          );

          let mut sets = Vec::with_capacity(new_sets_and_keys_and_stakes.len());
          let mut keys = HashMap::with_capacity(new_sets_and_keys_and_stakes.len());
          let mut stakes = HashMap::with_capacity(new_sets_and_keys_and_stakes.len());
          let mut total_stake = 0;
          for (set, key, stake) in new_sets_and_keys_and_stakes {
            sets.push(set);
            keys.insert(set.network, key);
            stakes.insert(set.network, stake.0);
            total_stake += stake.0;
          }

          if GenesisTime::get(&txn).is_none() {
            let time = serai_block.header.unix_time_in_millis();
            if time > 0 {
              GenesisTime::set(&mut txn, &time);
            }
          }

          if total_stake == 0 {
            let genesis_time = GenesisTime::get(&txn)
              // critical panic:
              // this is a critical issue and will not be solved after re-tries,
              // missing GenesisTime from previous blocks will remain missing until re-indexed (if encountered)
              // halt the process
              .expect("no genesis time for block #{block_number}");
            let time_elapsed_since_genesis =
              serai_block.header.unix_time_in_millis().saturating_sub(genesis_time);
            let genesis_period_end_timestamp =
              genesis_time + u64::try_from(GENESIS_LIQUIDITY_PERIOD.as_millis()).unwrap();

            if time_elapsed_since_genesis >= genesis_period_end_timestamp {
              // critical panic:
              // this is a critical issue and will not be solved after re-tries,
              // missing Stakes from previous blocks will remain missing until re-indexed (if encountered)
              // halt the process
              panic!("cosigning sets for block #{block_number} had 0 stake in total, while stake is required");
            }

            // Genesis era not ended period: assign equal stake to each validator set
            for set in &sets {
              stakes.insert(set.network, 1);
            }
            total_stake = u64::try_from(sets.len()).unwrap();
          }

          let next_global_session_info = GlobalSession {
            // This session starts cosigning after this block, as this block must be cosigned by
            // the existing validators
            start_block_number: block_number + 1,
            sets,
            keys,
            stakes,
            total_stake,
          };
          GlobalSessions::set(&mut txn, new_global_session, &next_global_session_info);
          if let Some(ending_global_session) = global_session_for_this_block {
            GlobalSessionsLastBlock::set(&mut txn, ending_global_session, &block_number);
          }
          LatestGlobalSessionIntended::set(&mut txn, &new_global_session);
          GlobalSessionsChannel::send(&mut txn, &(new_global_session, next_global_session_info));
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
              // critical panic: basically unreachable given the condition above this match
              .expect("global session for this block was None but still attempting to cosign it");

            // The GlobalSession that is ending
            let ending_global_session_info =
              GlobalSessions::get(&txn, global_session_for_this_block)
                // critical panic: something that went wrong above
                .expect("last global session intended wasn't saved to the database");

            // Tell each set of their expectation to cosign this block
            for set in ending_global_session_info.sets {
              #[cfg(not(coverage))]
              log::debug!("set will cosign block: set={set:?}, block_number={block_number}");

              IntendedCosigns::send(
                &mut txn,
                set,
                &CosignIntent {
                  global_session: global_session_for_this_block,
                  block_number,
                  block_hash: serai_block_hash,
                  notable: has_events == HasEvents::Notable,
                },
              );
            }
          }
          HasEvents::No => {}
        }

        #[cfg(not(coverage))]
        log::debug!("finished iterating: has_events={has_events:?}");

        // Populate a singular feed with every block's status for the evaluator to work off of
        BlockEvents::send(&mut txn, &(BlockEventData { block_number, has_events }));
        // Mark this block as handled, meaning we should scan from the next block moving on
        ScanCosignFrom::set(&mut txn, &(block_number + 1));

        // Commit for every block that did progress, on failure restarts from the next block
        txn.commit();
        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
