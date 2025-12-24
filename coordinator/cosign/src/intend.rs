use core::future::Future;
use std::collections::HashMap;

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
    validator_sets, Event,
  },
  Events,
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
  serai: &impl SeraiRpc,
  block_number: u64,
) -> Result<(Block, Events, HasEvents), String> {
  let block = match serai.block_by_number(block_number).await {
    Ok(Some(block)) => block,
    Ok(None) => return Err("couldn't get block which should've been finalized".to_owned()),
    Err(e) => return Err(format!("RPC error fetching block #{block_number}: {e}")),
  };
  let events = match serai.events(block.header.hash()).await {
    Ok(events) => events,
    Err(e) => return Err(format!("RPC error fetching events for block #{block_number}: {e}")),
  };

  if events.validator_sets().set_keys_events().next().is_some() {
    return Ok((block, events, HasEvents::Notable));
  }

  if events.coins().burn_with_instruction_events().next().is_some() {
    return Ok((block, events, HasEvents::NonNotable));
  }

  Ok((block, events, HasEvents::No))
}

// Fetch the `ExternalValidatorSet`s, and their associated keys, used for cosigning as of this
// block.
fn cosigning_sets(getter: &impl Get) -> Vec<(ExternalValidatorSet, Public, Amount)> {
  let mut sets = vec![];
  for network in ExternalNetworkId::all() {
    let Some(Set { session, key, stake }) = LatestSet::get(getter, network) else {
      // If this network doesn't have usable keys, move on
      continue;
    };

    sets.push((ExternalValidatorSet { network, session }, key, stake));
  }
  sets
}

/// A task to determine which blocks we should intend to cosign.
pub(crate) struct CosignIntendTask<D: Db, S: SeraiRpc> {
  pub(crate) db: D,
  pub(crate) serai: S,
}

impl<D: Db, S: SeraiRpc> ContinuallyRan for CosignIntendTask<D, S> {
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let start_block_number = ScanCosignFrom::get(&self.db).unwrap_or(1);
      let latest_block_number = match self.serai.latest_finalized_block_number().await {
        Ok(n) => n,
        Err(e) => return Err(format!("RPC error fetching latest finalized block number: {e}")),
      };

      if latest_block_number < start_block_number {
        return Ok(false);
      }

      for block_number in start_block_number..=latest_block_number {
        let mut txn = self.db.txn();

        let (block, events, mut has_events) =
          block_has_events_justifying_a_cosign(&self.serai, block_number).await?;

        let mut builds_upon =
          BuildsUpon::get(&txn).unwrap_or(IncrementalUnbalancedMerkleTree::new());

        // Check we are indexing a linear chain
        if block.header.builds_upon()
          != builds_upon.clone().calculate(serai_client_serai::abi::BLOCK_HEADER_BRANCH_TAG)
        {
          // nothing to commit
          drop(txn);
          return Err(format!(
            "node's block #{block_number} doesn't build upon the block #{} prior indexed",
            block_number - 1
          ))?;
        }
        let block_hash = block.header.hash();
        SubstrateBlockHash::set(&mut txn, block_number, &block_hash);
        builds_upon.append(
          serai_client_serai::abi::BLOCK_HEADER_BRANCH_TAG,
          Blake2b256::new_with_prefix([serai_client_serai::abi::BLOCK_HEADER_LEAF_TAG])
            .chain_update(block_hash.0)
            .finalize()
            .into(),
        );
        BuildsUpon::set(&mut txn, &builds_upon);

        // Update the stakes
        for tx_events in events.events() {
          for event in tx_events {
            match event {
              Event::ValidatorSets(event) => match event {
                validator_sets::Event::Allocation { validator, network, amount } => {
                  let Ok(network) = ExternalNetworkId::try_from(*network) else { continue };
                  let existing = Stakes::get(&txn, network, *validator).unwrap_or(Amount(0));
                  Stakes::set(&mut txn, network, *validator, &Amount(existing.0 + amount.0));
                }
                validator_sets::Event::Deallocation { validator, network, amount, timeline: _ } => {
                  let Ok(network) = ExternalNetworkId::try_from(*network) else { continue };
                  let existing = Stakes::get(&txn, network, *validator).unwrap_or(Amount(0));
                  Stakes::set(
                    &mut txn,
                    network,
                    *validator,
                    &Amount(existing.0.saturating_sub(amount.0)),
                  );
                }
                validator_sets::Event::SetDecided { set, validators } => {
                  let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };
                  Validators::set(
                    &mut txn,
                    set,
                    &validators.iter().map(|(validator, _key_shares)| *validator).collect(),
                  );
                }
                validator_sets::Event::SetKeys { set, key_pair } => {
                  let mut stake = 0;
                  for validator in
                    Validators::take(&mut txn, *set).expect("set which wasn't decided set keys")
                  {
                    stake += Stakes::get(&txn, set.network, validator).unwrap_or(Amount(0)).0;
                  }
                  LatestSet::set(
                    &mut txn,
                    set.network,
                    &Set { session: set.session, key: key_pair.0, stake: Amount(stake) },
                  );
                }
                _ => continue,
              },
              _ => continue,
            }
          }
        }

        let global_session_for_this_block = LatestGlobalSessionIntended::get(&txn);

        // If this is notable, it creates a new global session, which we index into the database
        // now
        if has_events == HasEvents::Notable {
          let sets_and_keys_and_stakes = cosigning_sets(&txn);
          let global_session = GlobalSession::id(
            sets_and_keys_and_stakes.iter().map(|(set, _key, _stake)| *set).collect(),
          );

          let mut sets = Vec::with_capacity(sets_and_keys_and_stakes.len());
          let mut keys = HashMap::with_capacity(sets_and_keys_and_stakes.len());
          let mut stakes = HashMap::with_capacity(sets_and_keys_and_stakes.len());
          let mut total_stake = 0u64;
          for (set, key, stake) in sets_and_keys_and_stakes {
            sets.push(set);
            keys.insert(set.network, key);
            stakes.insert(set.network, stake.0);
            total_stake = total_stake.saturating_add(stake.0);
          }
          if total_stake == 0 {
            // commit only per block finished otherwise reset progress
            drop(txn);
            return Err(format!("cosigning sets for block #{block_number} had 0 stake in total"))?;
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
              #[cfg(not(coverage))]
              log::debug!("{set:?} will be cosigning block #{block_number}");
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

        // Populate a singular feed with every block's status for the evaluator to work off of
        BlockEvents::send(&mut txn, &(BlockEventData { block_number, has_events }));
        // Mark this block as handled, meaning we should scan from the next block moving on
        ScanCosignFrom::set(&mut txn, &(block_number + 1));

        // All-or-nothing, commit only per block finished otherwise reset progress
        txn.commit();
      }

      Ok(true)
    }
  }
}
