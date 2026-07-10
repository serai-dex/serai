use core::future::Future;
#[cfg(test)]
use core::time::Duration;
use std::{sync::Arc, collections::HashMap};

use blake2::Blake2b256;

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

use serai_task::ContinuallyRan;

use crate::*;

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub(crate) struct Set {
  pub(crate) session: Session,
  pub(crate) key: Public,
  pub(crate) stake: Amount,
}

serai_db::schema!(
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

serai_db::channel! {
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
pub(crate) struct CosignIntendTask<D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>> {
  pub(crate) db: D,
  pub(crate) serai: Arc<Serai>,
}

impl<D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>> ContinuallyRan
  for CosignIntendTask<D>
{
  #[cfg(test)]
  const DELAY_BETWEEN_ITERATIONS: Duration = Duration::from_secs(1);
  #[cfg(test)]
  const MAX_DELAY_BETWEEN_ITERATIONS: Duration = Duration::from_secs(5);

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

      let mut made_progress = false;

      for block_number in start_scan_block_number ..= latest_serai_block_number {
        let serai_block = self
          .serai
          .block_by_number(block_number)
          .await
          // Ephemeral RPC Err: task to re-run and continue trying
          .map_err(|e| format!("RPC error fetching block #{block_number}: {e}"))?
          // Block returned `None` even though Serai reported as finalized
          .unwrap_or_else(|| {
            panic!("couldn't get block #{block_number} which should've been finalized")
          });

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
        assert_eq!(
          serai_block.header.builds_upon(),
          builds_upon.clone().calculate(serai_client_serai::abi::BLOCK_BRANCH_TAG),
          "node's block #{block_number} doesn't build upon the block #{} prior indexed",
          block_number - 1
        );
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
            // Not an `ExternalNetworkId` and therefore would be a Serai network allocation
            // safe to just skip this allocation event
            continue;
          };

          let existing = Stakes::get(&txn, network, *validator).unwrap_or(Amount(0));
          Stakes::set(&mut txn, network, *validator, &Amount(existing.0 + amount.0));
        }
        for event in vset_events.deallocation_events() {
          let Event::Deallocation { validator, network, amount, timeline: _ } = event else {
            unreachable!("event from `deallocation_events` wasn't `Event::Deallocation`")
          };
          let Ok(network) = ExternalNetworkId::try_from(*network) else {
            // Not an `ExternalNetworkId` and therefore would be a Serai network allocation
            // safe to skip this deallocation event
            continue;
          };

          let existing = Stakes::get(&txn, network, *validator).unwrap_or(Amount(0));
          Stakes::set(&mut txn, network, *validator, &Amount(existing.0 - amount.0));
        }

        // Handle decided sets
        for event in vset_events.set_decided_events() {
          let Event::SetDecided { set, validators } = event else {
            unreachable!("event from `set_decided_events` wasn't `Event::SetDecided`")
          };

          let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };

          assert!(!validators.is_empty(), "validator set from Event::SetDecided was empty");

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

          /*
            Clear any prior declared set.

            This is needed in case this set isn't saved due to being without stake. In that case,
            if a historic set had stake, the historic set would still be regarded as latest despite
            being historic.

            TODO: Handle a set retiring when not followed by a new set (currently unreachable).
          */
          LatestSet::take(&mut txn, set.network);

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
          if stake > 0 {
            has_events = has_events.max(HasEvents::Notable);
            LatestSet::set(
              &mut txn,
              set.network,
              &Set { session: set.session, key: key_pair.0, stake: Amount(stake) },
            );
          }
        }

        // Handle burn with instruction events (makes block non-notable if not already notable)
        if serai_block_events.coins().burn_with_instruction_events().next().is_some() {
          has_events = has_events.max(HasEvents::NonNotable);
        }

        let global_session_for_this_block = LatestGlobalSessionIntended::get(&txn);

        // If this is notable, it creates a new global session, which we index into the database
        // now
        if has_events == HasEvents::Notable {
          let new_sets_and_keys_and_stakes = cosigning_sets(&txn);
          assert!(
            !new_sets_and_keys_and_stakes.is_empty(),
            "notable event yet no sets for cosigning"
          );
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

            // This filtering occurs when we populate `LatestSet`
            assert!(
              stake != Amount(0),
              "set without stake was selected for cosigning when stake is required"
            );
            stakes.insert(set.network, stake.0);
            total_stake += stake.0;
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
              // panic: invariant, this is checked above
              .expect("global session for this block was None but still attempting to cosign it");

            let global_session_for_this_block_info =
              GlobalSessions::get(&txn, global_session_for_this_block)
                // panic: invariant, this has to exist by this point
                .expect("last global session intended wasn't saved to the database");

            // Tell each set of their expectation to cosign this block
            for set in global_session_for_this_block_info.sets {
              serai_env::info!("{set:?} will cosign block #{block_number} ({has_events:?})");

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
