use core::future::Future;
use std::{sync::Arc, collections::HashMap};

use blake2::{Digest as _, Blake2b256};

use serai_client_serai::{
  abi::{
    primitives::{
      network_id::ExternalNetworkId,
      balance::Amount,
      crypto::Public,
      validator_sets::{Session, ExternalValidatorSet},
      address::SeraiAddress,
      merkle::IncrementalUnbalancedMerkleTree,
    },
    validator_sets::Event,
  },
  Serai,
};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::*;

#[derive(Debug, BorshSerialize, BorshDeserialize)]
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
  #[cfg(test)]
  const DELAY_BETWEEN_ITERATIONS: u64 = 1;
  #[cfg(test)]
  const MAX_DELAY_BETWEEN_ITERATIONS: u64 = 5;

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

      serai_env::trace!(
        "beginning intend scan: start={start_scan_block_number}, latest={latest_serai_block_number}"
      );

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
          .events(serai_block_hash)
          .await
          // Ephemeral RPC Err: task to re-run and continue trying
          .map_err(|e| format!("RPC error fetching events for block #{block_number}: {e}"))?;

        let mut txn = self.db.txn();
        let mut builds_upon =
          BuildsUpon::get(&txn).unwrap_or(IncrementalUnbalancedMerkleTree::new());

        // Check we are indexing a linear chain
        if serai_block.header.builds_upon() !=
          builds_upon.clone().calculate(serai_client_serai::abi::BLOCK_BRANCH_TAG)
        {
          // Ephemeral RPC Err:
          // serai.block_by_number(block_number) may have returned a different chain history
          // from prior indexed block already finalized,
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

        serai_env::trace!("iterating over block_number={block_number}");

        let mut has_events = HasEvents::No;
        let vset_events = serai_block_events.validator_sets();

        // Update the stakes
        for event in vset_events.allocation_events() {
          let Event::Allocation { validator, network, amount } = event else {
            unreachable!("event from `allocation_events` wasn't `Event::Allocation`")
          };
          let Ok(network) = ExternalNetworkId::try_from(*network) else {
            // Not an ExternalNetworkId, possible Serai network allocation
            // safe to just skip this allocation event
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
            // missing Stakes from previous blocks will remain missing until re-indexed
            // if encountered halt the process
            .expect("unable to deallocate with no prior indexed Stake");

          Stakes::set(&mut txn, network, *validator, &Amount(existing.0 - amount.0));
        }

        // Handle decided sets
        for event in vset_events.set_decided_events() {
          let Event::SetDecided { set, validators } = event else {
            unreachable!("event from `set_decided_events` wasn't `Event::SetDecided`")
          };

          let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };

          if validators.is_empty() {
            panic!("validator set from Event::SetDecided was empty");
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

          let validators = Validators::take(&mut txn, *set)
            // critical panic:
            // this is a critical issue and will not be solved after re-tries,
            // missing Validators from previous blocks will remain missing until re-indexed
            // if encountered halt the process
            .expect("set which wasn't decided set keys");

          let stake: u64 = validators
            .iter()
            .map(|v| Stakes::get(&txn, set.network, *v).unwrap_or(Amount(0)).0)
            .sum();

          // Sets with 0 stake should be skipped and not considered w.r.t. cosigning
          // for no set with stake then has_events will remain HasEvents::No for this block and ignored
          if stake > 0 {
            has_events = HasEvents::Notable;
            LatestSet::set(
              &mut txn,
              set.network,
              &Set { session: set.session, key: key_pair.0, stake: Amount(stake) },
            );
          } else {
            serai_env::trace!(
              "{block_number}: skipped session {:?} of {:?} with 0 stake from being selected for cosigns",
              set.session,
              set.network
            );
          }
        }

        // Handle burn with instruction events (makes block non-notable if not already notable)
        if has_events == HasEvents::No {
          if serai_block_events.coins().burn_with_instruction_events().next().is_some() {
            has_events = HasEvents::NonNotable;
          }
        }

        let global_session_for_this_block = LatestGlobalSessionIntended::get(&txn);

        serai_env::trace!("{block_number}: type of has_events={has_events:?}");

        // If this is notable, it creates a new global session, which we index into the database
        // now
        if has_events == HasEvents::Notable {
          let new_sets_and_keys_and_stakes = cosigning_sets(&txn);
          let new_global_session = GlobalSession::id(
            new_sets_and_keys_and_stakes.iter().map(|(set, _key, _stake)| *set).collect(),
          );

          let length = new_sets_and_keys_and_stakes.len();
          let mut sets = Vec::with_capacity(length);
          let mut keys = HashMap::with_capacity(length);
          let mut stakes = HashMap::with_capacity(length);
          let mut total_stake = 0;
          for (set, key, stake) in new_sets_and_keys_and_stakes {
            sets.push(set);
            keys.insert(set.network, key);
            stakes.insert(set.network, stake.0);
            total_stake += stake.0;
          }

          if total_stake == 0 {
            // critical panic:
            // this is a critical issue and will not be solved after re-tries,
            // missing Stakes greater than zero from previous blocks will remain missing until re-indexed
            // if encountered halt the process
            panic!("cosigning sets for block #{block_number} had 0 stake in total, while stake is required");
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

          serai_env::trace!(
            "{block_number}: Notable block block_number={block_number}: new session created \
           start_block_number={start_block}, sets={sets:?}, \
           stakes={stakes:?}, total_stake={total_stake}",
            start_block = next_global_session_info.start_block_number,
            sets = next_global_session_info.sets,
            stakes = next_global_session_info.stakes,
          );

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
        if (has_events != HasEvents::No) && global_session_for_this_block.is_none() {
          serai_env::trace!(
            "{block_number}: no previous global session available to cosign, has_events = HasEvents::No"
          );
          has_events = HasEvents::No;
        }

        match has_events {
          HasEvents::Notable | HasEvents::NonNotable => {
            let global_session_for_this_block = global_session_for_this_block
              // panic: invariant, this is checked above
              .expect("global session for this block was None but still attempting to cosign it");

            // The GlobalSession that is ending
            let ending_global_session_info =
              GlobalSessions::get(&txn, global_session_for_this_block)
                // panic: invariant, this has to exist by this point
                .expect("last global session intended wasn't saved to the database");

            // Tell each set of their expectation to cosign this block
            for set in ending_global_session_info.sets {
              serai_env::prod_info!(
                "{block_number}: set will cosign {has_events:?} block: set={set:?}, block_number={block_number}"
              );

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

        serai_env::trace!(
          "finished iterating block_number={block_number}: has_events={has_events:?}"
        );

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
