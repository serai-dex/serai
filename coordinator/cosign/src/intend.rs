//! Scans the serai blockchain for cosigns which are intended to be performed
//! and indexes relevant entries to the DB for future use and for catching faults.
use core::future::Future;
#[cfg(test)]
use core::time::Duration;
use std::{sync::Arc, collections::HashMap};

use blake2::{Digest as _, Blake2b256};

use serai_client_serai::{
  abi::{
    self,
    primitives::{
      network_id::{NetworkId, ExternalNetworkId},
      balance::Amount,
      crypto::{
        Public, SeraiNetworksAuxiliaryKey, EmbeddedEllipticCurveKeys as AuxiliaryKeysStruct,
      },
      validator_sets::{Session, ExternalValidatorSet},
      address::SeraiAddress,
      merkle::{IncrementalUnbalancedMerkleTree, UnbalancedMerkleTree},
    },
    validator_sets::Event,
  },
  Serai,
};

use serai_db::*;
use serai_task::{ContinuallyRan, FuturesRangeProcessor};

use crate::*;

#[derive(Debug, BorshSerialize, BorshDeserialize)]
/// A cosigning set for a given network.
pub(crate) struct NetworksCosigningSet {
  pub(crate) session: Session,
  pub(crate) key: Public,
  pub(crate) stake: Amount,
}

create_db!(
  CosignIntend {
    // Which block number to start scanning intends from next.
    ScanIntendBlocksFrom: () -> u64,
    // Merkle tree of block hashes to verify linear chain continuity being cosigned.
    BuildsUpon: () -> IncrementalUnbalancedMerkleTree,
    // Validators' auxiliary keys at the time of set declaration, per network, as a
    // history-preserving Vec.
    //
    // Each `SetEmbeddedEllipticCurveKeys` event appends to the Vec for its
    // `(network, validator/identity)` pair. Use `AuxiliaryKeys::get` to retrieve the
    // **latest** auxiliary key published by that validator for that network.
    //
    // For the coordinator to run properly the `SERAI_KEY` env var used in
    // `coordinator/src/main.rs` MUST correspond to the **latest** NetworkId::Serai
    // auxiliary key used to identify itself. The presence of history allows for
    // getting all historical auxiliary keys and calculating the total stake stored
    // for this validator, for example. Right now only total stake per network is
    // used but individual validators' stake would come in useful per the fallback
    // protocol specified in the README.md.
    NetworksValidatorAuxiliaryKeys:
      (network: NetworkId, identity: SeraiAddress) -> Vec<AuxiliaryKeysStruct>,
    // Every network participants' stake amounts.
    NetworksValidatorStakes:
      (network: ExternalNetworkId, validator: SeraiNetworksAuxiliaryKey) -> Option<Amount>,
    // Validators of a given network in a decided but not yet active cosigning set,
    // pending a SetKeys event to take out their entries.
    NetworksPendingValidators: (set: ExternalValidatorSet) -> Vec<SeraiNetworksAuxiliaryKey>,
    // Latest active validator set for each network, used for cosigning.
    NetworksLatestSet: (network: ExternalNetworkId) -> NetworksCosigningSet,
  }
);

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub(crate) struct BlockEventData {
  pub(crate) block_number: u64,
  pub(crate) has_events: HasEvents,
}

db_channel! {
  CosignIntendChannels {
    // Per-block status feed sent by the intend task for every processed block's evaluation.
    // Every serai block is index and sent through this channel for the evaluator task.
    BlockEvents: () -> BlockEventData,
    // Newly-begun global cosigning sessions, sent by the intend task when a
    // notable block starts a new global cosigning session and drained by the evaluator
    // task to begin evaluating it.
    GlobalCosigningSessionsChannel: () -> (GlobalCosigningSessionId, GlobalCosigningSession),
    // Per validator set queue of `CosignIntent`s, populated by the intend task when a
    // block has cosign events. Drained by `Cosigning::intended_cosigns`, which pulls
    // all pending non-notable cosigns and stops up to and including the next notable one.
    NetworksIntendedCosigns: (set: ExternalValidatorSet) -> CosignIntent,
  }
}

/// Get the latest indexed `NetworkId::Serai` auxiliary key for a validator.
/// used through the coordinator to identify itself.
pub(crate) fn serai_networks_auxiliary_key(
  getter: &impl Get,
  identity: SeraiAddress,
) -> SeraiNetworksAuxiliaryKey {
  match AuxiliaryKeys::get(getter, NetworkId::Serai, identity)
    .expect("Auxiliary key must exist for validator.")
  {
    AuxiliaryKeysStruct::Serai(substrate) => {
      SeraiNetworksAuxiliaryKey::from_bytes(substrate).expect("invalid auxiliary key")
    }
    AuxiliaryKeysStruct::Bitcoin(..) |
    AuxiliaryKeysStruct::Ethereum(..) |
    AuxiliaryKeysStruct::Monero(..) => {
      unreachable!("NetworkId::Serai auxiliary key cannot match an external network")
    }
  }
}

/// Data fetched from Serai for a single block, used by [`FuturesRangeProcessor`].
pub struct IntendBlockData {
  block_hash: BlockHash,
  builds_upon: UnbalancedMerkleTree,
  events: serai_client_serai::Events,
}

/// A task to determine which blocks we should intend to cosign.
pub(crate) struct CosignIntendTask<D: Db> {
  pub(crate) db: D,
  pub(crate) serai: Arc<Serai>,
}

impl<D: Db> CosignIntendTask<D> {
  /// Fetch all the latest `ExternalValidatorSet`s, and their associated keys, used for cosigning
  /// as of this block.
  fn all_latest_cosigning_sets(getter: &impl Get) -> Vec<(ExternalValidatorSet, Public, Amount)> {
    ExternalNetworkId::all()
      .filter_map(|network| {
        let NetworksCosigningSet { session, key, stake } = NetworksLatestSet::get(getter, network)?;
        Some((ExternalValidatorSet { network, session }, key, stake))
      })
      .collect()
  }
}

impl<D: Db> ContinuallyRan for CosignIntendTask<D> {
  #[cfg(test)]
  const DELAY_BETWEEN_ITERATIONS: Duration = Duration::from_secs(1);
  #[cfg(test)]
  const MAX_DELAY_BETWEEN_ITERATIONS: Duration = Duration::from_secs(5);

  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let start_scan_block_number = ScanIntendBlocksFrom::get(&self.db).unwrap_or(0);
      let latest_serai_block_number = self
        .serai
        .latest_finalized_block_number()
        .await
        // Ephemeral RPC Err: task to re-run and continue trying
        .map_err(|e| format!("RPC error fetching latest finalized block number: {e}"))?;

      self.process_range(start_scan_block_number, latest_serai_block_number).await
    }
  }
}

impl<D: Db> FuturesRangeProcessor for CosignIntendTask<D> {
  type Item = IntendBlockData;
  const ITEMS_TO_PROCESS_AT_ONCE: u64 = 10;

  fn fetch_item(
    &self,
    block_number: u64,
  ) -> impl Send + 'static + Future<Output = Result<(u64, Self::Item), Self::Error>> {
    let serai = self.serai.clone();
    async move {
      let serai_block = serai
        .block_by_number(block_number)
        .await
        // Ephemeral RPC Err: task to re-run and continue trying
        .map_err(|e| format!("RPC error fetching block #{block_number}: {e}"))?
        // Block returned `None` even though Serai reported as finalized
        .unwrap_or_else(|| {
          panic!("couldn't get block #{block_number} which should've been finalized")
        });

      let block_hash = serai_block.header.hash();
      let builds_upon = serai_block.header.builds_upon();

      let events = serai
        .events(block_hash)
        .await
        // Ephemeral RPC Err: task to re-run and continue trying
        .map_err(|e| format!("RPC error fetching events for block #{block_number}: {e}"))?;

      Ok((block_number, IntendBlockData { block_hash, builds_upon, events }))
    }
  }

  fn process_item(&mut self, block_number: u64, data: Self::Item) -> Result<(), Self::Error> {
    let mut txn = self.db.txn();
    let mut builds_upon = BuildsUpon::get(&txn).unwrap_or(IncrementalUnbalancedMerkleTree::new());

    // Check we are indexing a linear chain
    assert_eq!(
      data.builds_upon,
      builds_upon.clone().calculate(serai_client_serai::abi::BLOCK_BRANCH_TAG),
      "node's block #{block_number} doesn't build upon the block #{} prior indexed",
      block_number - 1
    );
    crate::SubstrateBlockHash::set(&mut txn, block_number, &data.block_hash);
    builds_upon.append(
      serai_client_serai::abi::BLOCK_BRANCH_TAG,
      Blake2b256::new_with_prefix([serai_client_serai::abi::BLOCK_LEAF_TAG])
        .chain_update(data.block_hash.0)
        .finalize()
        .into(),
    );
    BuildsUpon::set(&mut txn, &builds_upon);

    let mut has_events = HasEvents::No;
    let vset_events = data.events.validator_sets();

    // First, handle the auxiliary keys set events in the block
    for event in vset_events.set_embedded_elliptic_curve_keys_events() {
      let Event::SetEmbeddedEllipticCurveKeys { validator, keys } = &event else {
        unreachable!(
          "{}: {event:?}",
          "`SetEmbeddedEllipticCurveKeys` event wasn't a `SetEmbeddedEllipticCurveKeys` event"
        );
      };

      /*
        It's a documented invariant that all validators, for any network, must have this auxiliary
        key set. Currently, it's enforced by all genesis validators being required to set auxiliary
        keys for _every_ network, and auxiliary keys being required to be set _before_ stake may
        be allocated.

        As those are the only two ways to qualify to be selected as a validator, this invariant
        holds.
      */

      AuxiliaryKeys::set(&mut txn, keys.network(), *validator, keys);
    }

    // Second, update the stakes for this block
    for event in vset_events.allocation_events() {
      let Event::Allocation { validator, network, amount } = event else {
        unreachable!("event from `allocation_events` wasn't `Event::Allocation`")
      };

      // We only coordinate over external networks
      let Ok(network) = ExternalNetworkId::try_from(*network) else {
        continue;
      };

      let serai_networks_auxiliary_key = serai_networks_auxiliary_key(&txn, *validator);
      let existing_stake =
        Stakes::get(&txn, network, serai_networks_auxiliary_key).unwrap_or(Amount(0));
      Stakes::set(
        &mut txn,
        network,
        serai_networks_auxiliary_key,
        // serai protocol invariant: assumes that can add, overflow expected to panic
        &Some(Amount(existing_stake.0 + amount.0)),
      );
    }
    for event in vset_events.deallocation_events() {
      let Event::Deallocation { validator, network, amount, timeline: _ } = event else {
        unreachable!("event from `deallocation_events` wasn't `Event::Deallocation`")
      };

      // We only coordinate over external networks
      let Ok(network) = ExternalNetworkId::try_from(*network) else {
        continue;
      };

      let serai_networks_auxiliary_key = serai_networks_auxiliary_key(&txn, *validator);
      if let Some(existing_stake) = Stakes::get(&txn, network, serai_networks_auxiliary_key) {
        // serai protocol invariant: assumes that can subtract, overflow expected to panic
        let new_amount = existing_stake.0 - amount.0;
        if new_amount == 0 {
          // Instead of Amount(0) the stake is now None
          Stakes::set(&mut txn, network, serai_networks_auxiliary_key, &None);
        } else {
          Stakes::set(&mut txn, network, serai_networks_auxiliary_key, &Some(Amount(new_amount)));
        }
      }
    }

    // Third, handle new decided set events in the block,
    for event in vset_events.set_decided_events() {
      let Event::SetDecided { set, validators } = event else {
        unreachable!("event from `set_decided_events` wasn't `Event::SetDecided`")
      };

      // We only coordinate over external networks
      let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };

      assert!(!validators.is_empty(), "validator set from Event::SetDecided was empty");

      let validators_serai_networks_auxiliary_keys = &validators
        .iter()
        .map(|(validator, _)| serai_networks_auxiliary_key(&txn, *validator))
        .collect();

      NetworksPendingValidators::set(&mut txn, set, validators_serai_networks_auxiliary_keys);
    }

    // Fourth, handle declarations of the latest set
    for event in vset_events.set_keys_events() {
      let Event::SetKeys { set, key_pair } = event else {
        unreachable!("event from `set_keys_events` wasn't `Event::SetKeys`")
      };

      /*
        Clear any prior declared set.

        This is needed in case this set isn't saved due to being without stake. In that case,
        if a historic set had stake, the historic set would still be regarded as latest despite
        being historic.
      */
      NetworksLatestSet::take(&mut txn, set.network);

      let pending_network_validators = NetworksPendingValidators::take(&mut txn, *set)
        // critical panic:
        // this is a critical issue and will not be solved after re-tries,
        // missing PendingValidators from previous blocks will remain missing until re-indexed
        // if encountered halt the process
        .expect("set which wasn't decided set keys");

      let pending_network_stake: u64 = pending_network_validators
        .iter()
        .map(|v| Stakes::get(&txn, set.network, *v).unwrap_or(Amount(0)).0)
        .sum();

      // 0 stake external validator sets should be skipped and not considered w.r.t. cosigning
      if pending_network_stake > 0 {
        has_events = has_events.max(HasEvents::Notable);
        NetworksLatestSet::set(
          &mut txn,
          set.network,
          &NetworksCosigningSet {
            session: set.session,
            key: key_pair.0,
            stake: Amount(pending_network_stake),
          },
        );
      }
    }

    // Fifth, handle slashes reported events in the block
    for event in vset_events.slashes_events() {
      // We only coordinate over external networks
      let Event::Slashes(abi::validator_sets::ReportedSlashes::ExternalValidatorSet(set)) = event
      else {
        continue;
      };

      /*
        Handle a set retiring.

        This is needed to avoid the historic set still being regarded as latest despite
        being retired.
      */
      NetworksLatestSet::take(&mut txn, set.network);
      serai_env::info!("{set:?} will be retired after slashes were reported.");
    }

    // Handle burn with instruction events (makes block non-notable if not already notable)
    if data.events.coins().burn_with_instruction_events().next().is_some() {
      has_events = has_events.max(HasEvents::NonNotable);
    }

    // The pre-existing global cosigning session, if any already existed at this point
    // that will cosign this block before a new global cosigning session comes in
    let session_to_cosign_this_block = LatestGlobalCosigningSessionIntended::get(&txn);
    let latest_cosigning_sets_and_keys_and_stakes = Self::all_latest_cosigning_sets(&txn);

    if latest_cosigning_sets_and_keys_and_stakes.is_empty() {
      serai_env::info!(
        "Block {} had notable event, yet no sets for cosigning. skipping as nothing to handle",
        block_number
      );
      has_events = HasEvents::No;
    }

    // If notable, this creates a new global cosigning session, which we index into the database
    // now
    if has_events == HasEvents::Notable {
      assert!(
        !latest_cosigning_sets_and_keys_and_stakes.is_empty(),
        "notable event yet no sets for cosigning"
      );

      let next_global_cosigning_session = GlobalCosigningSession::id(
        latest_cosigning_sets_and_keys_and_stakes.iter().map(|(set, _key, _stake)| *set).collect(),
      );

      let mut cosigning_sets = Vec::with_capacity(latest_cosigning_sets_and_keys_and_stakes.len());
      let mut keys = HashMap::with_capacity(latest_cosigning_sets_and_keys_and_stakes.len());
      let mut stakes = HashMap::with_capacity(latest_cosigning_sets_and_keys_and_stakes.len());
      let mut total_stake = 0;
      for (set, key, stake) in latest_cosigning_sets_and_keys_and_stakes {
        cosigning_sets.push(set);
        keys.insert(set.network, key);

        // This filtering occurs when we populate `LatestSet`
        assert!(
          stake != Amount(0),
          "set without stake was selected for cosigning when stake is required"
        );
        stakes.insert(set.network, stake.0);
        // serai invariant: assumes that can add network stakes, overflow expected to panic
        total_stake += stake.0;
      }

      let next_global_cosigning_session_info = GlobalCosigningSession {
        // This session starts cosigning after this block, as this block must be cosigned by
        // the existing cosigning validators
        // serai invariant: assumes that can add to block_number, overflow expected to panic
        start_block_number: block_number + 1,
        cosigning_sets,
        keys,
        stakes,
        total_stake,
      };

      crate::GlobalCosigningSessions::set(
        &mut txn,
        next_global_cosigning_session,
        &next_global_cosigning_session_info,
      );
      // this global cosigning session is ending this block, set its final block number
      if let Some(ending_global_cosigning_session) = session_to_cosign_this_block {
        crate::GlobalCosigningSessionsLastBlock::set(
          &mut txn,
          ending_global_cosigning_session,
          &block_number,
        );
      }
      // set the new global cosigning session as the latest
      LatestGlobalCosigningSessionIntended::set(&mut txn, &next_global_cosigning_session);
      GlobalCosigningSessionsChannel::send(
        &mut txn,
        &(next_global_cosigning_session, next_global_cosigning_session_info),
      );
    }

    // If there isn't anyone available to cosign this block, meaning it'll never be cosigned,
    // we flag it as not having any events requiring cosigning so we don't attempt to
    // sign/require a cosign for it
    if session_to_cosign_this_block.is_none() {
      has_events = HasEvents::No;
    }

    match has_events {
      HasEvents::Notable | HasEvents::NonNotable => {
        let global_cosigning_session_for_this_block = session_to_cosign_this_block
          // panic: invariant, this is guaranteed to exist above
          .expect(
            "global cosigning session for this block was None but still attempting to cosign it",
          );

        let global_cosigning_session_for_this_block_info =
          GlobalCosigningSessions::get(&txn, global_cosigning_session_for_this_block)
            // panic: invariant, this has to exist by this point
            .expect("last global cosigning session intended wasn't saved to the database");

        // Tell each set of their expectation to cosign this block
        for cosigning_set in global_cosigning_session_for_this_block_info.cosigning_sets {
          serai_env::info!("{cosigning_set:?} will cosign block #{block_number} ({has_events:?})");

          NetworksIntendedCosigns::send(
            &mut txn,
            cosigning_set,
            &CosignIntent {
              global_cosigning_session: global_cosigning_session_for_this_block,
              block_number,
              block_hash: data.block_hash,
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
    ScanIntendBlocksFrom::set(&mut txn, &(block_number + 1));
    // Commit for every block that did progress, on failure restarts from the next block
    txn.commit();
    Ok(())
  }
}

/// Every network participants' stake amounts.
pub struct Stakes;
impl Stakes {
  /// Store Stakes per validator per network.
  pub fn set(
    txn: &mut impl DbTxn,
    network: ExternalNetworkId,
    validator: SeraiNetworksAuxiliaryKey,
    amount: &Option<Amount>,
  ) {
    NetworksValidatorStakes::set(txn, network, validator, amount);
  }
  /// Try to get stored Stakes per validator per network,
  /// returns `None` if stake have not been indexed by intend or
  /// the validator has no stake
  pub fn get(
    getter: &impl Get,
    network: ExternalNetworkId,
    validator: SeraiNetworksAuxiliaryKey,
  ) -> Option<Amount> {
    NetworksValidatorStakes::get(getter, network, validator).unwrap_or(None)
  }
}

/// Every validator's auxiliary keys per network.
pub struct AuxiliaryKeys;
impl AuxiliaryKeys {
  /// Store auxiliary keys per validator per network, appending to the history.
  pub fn set(
    txn: &mut impl DbTxn,
    network: NetworkId,
    identity: SeraiAddress,
    keys: &AuxiliaryKeysStruct,
  ) {
    let mut keys_list =
      NetworksValidatorAuxiliaryKeys::get(txn, network, identity).unwrap_or_default();
    keys_list.push(*keys);
    NetworksValidatorAuxiliaryKeys::set(txn, network, identity, &keys_list);
  }

  /// Try to get the latest auxiliary keys per validator per network,
  /// returns `None` if auxiliary keys have not been indexed by intend.
  pub fn get(
    getter: &impl Get,
    network: NetworkId,
    identity: SeraiAddress,
  ) -> Option<AuxiliaryKeysStruct> {
    NetworksValidatorAuxiliaryKeys::get(getter, network, identity)?.into_iter().last()
  }
}
