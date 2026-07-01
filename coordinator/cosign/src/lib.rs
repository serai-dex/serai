#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

use core::{fmt::Debug, future::Future};
use std::{sync::Arc, collections::HashMap, time::Instant};

#[cfg(test)]
use tokio::task::JoinHandle;

use blake2::{Digest as _, Blake2s256};

use borsh::{BorshSerialize, BorshDeserialize};

use serai_client_serai::{
  abi::primitives::{
    BlockHash,
    crypto::{Public, EmbeddedEllipticCurveKeys as AuxiliaryKeysStruct, SeraiNetworksAuxiliaryKey},
    network_id::{NetworkId, ExternalNetworkId},
    validator_sets::ExternalValidatorSet,
    address::SeraiAddress,
  },
  Serai,
};

use serai_db::*;
use serai_task::*;

pub use serai_cosign_types::*;

/// The cosigns which are intended to be performed.
pub mod intend;

/// Get the latest indexed `NetworkId::Serai` auxiliary key for a validator.
/// Indexed by the cosign intend task and used through the coordinator as its identity.
pub fn serai_networks_auxiliary_key(
  getter: &impl Get,
  identity: SeraiAddress,
) -> SeraiNetworksAuxiliaryKey {
  intend::serai_networks_auxiliary_key(getter, identity)
}

/// The auxiliary keys indexed as an Event::SetEmbeddedEllipticCurveKeys
pub struct AuxiliaryKeys;
impl AuxiliaryKeys {
  /// Try to get stored AuxiliaryKeys per validator,
  /// returns `None` if auxiliary keys have not been indexed by intend.
  pub fn get(
    getter: &impl Get,
    network: NetworkId,
    identity: SeraiAddress,
  ) -> Option<AuxiliaryKeysStruct> {
    intend::AuxiliaryKeys::get(getter, network, identity)
  }
}

/// Validators of a given network in a decided but not yet active cosigning set,
///
/// These are validators for sets which have been decided on-chain (via `SetDecided`) but have
/// not yet been activated (via `SetKeys`). Once `SetKeys` is processed, the entry is removed.
pub struct PendingValidators;
impl PendingValidators {
  /// Try to get stored PendingValidators per external validator set,
  /// returns `None` if pending validators have not been indexed by intend.
  pub fn get(
    getter: &impl Get,
    set: ExternalValidatorSet,
  ) -> Option<Vec<SeraiNetworksAuxiliaryKey>> {
    intend::NetworksPendingValidators::get(getter, set)
  }
  /// Check whether a given validator set is still pending activation.
  pub fn is_pending(getter: &impl Get, set: ExternalValidatorSet) -> bool {
    Self::get(getter, set).is_some()
  }
}

/// The evaluator of the cosigns.
mod evaluator;
/// The task to delay acknowledgement of the cosigns.
mod delay;
pub use delay::BROADCAST_FREQUENCY;
use delay::LatestCosignedBlockNumber;

/// Test helpers and fixtures.
#[cfg(test)]
pub mod tests;

/// Utilities for seeding the cosign DB in tests and test-helper contexts.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;

pub(crate) const COSIGN_FAULT_THRESHOLD_NUMERATOR: u128 = 17;
pub(crate) const COSIGN_FAULT_THRESHOLD_DENOMINATOR: u128 = 100;

/// Calculate the minimum threshold required for faulting a cosigning session.
pub(crate) fn cosign_fault_threshold(total_stake: u64) -> u64 {
  const {
    assert!(crate::COSIGN_FAULT_THRESHOLD_NUMERATOR < crate::COSIGN_FAULT_THRESHOLD_DENOMINATOR);
  }
  u64::try_from(
    (u128::from(total_stake) * crate::COSIGN_FAULT_THRESHOLD_NUMERATOR) /
      crate::COSIGN_FAULT_THRESHOLD_DENOMINATOR,
  )
  .expect("threshold < 1") +
    1
}

/// A 'global cosigning session': all validator sets used for cosigning at a given moment.
///
/// We evaluate cosign faults within a global cosigning session. Even if cosigners cosign
/// distinct blocks at distinct positions within a session, we still identify the faults.
/*
  There is the attack where a validator set is given an alternate blockchain with a key generation
  event at block #n, while most validator sets are given a blockchain with a key generation event
  at block number #(n+1). This prevents whoever has the alternate blockchain from verifying the
  cosigns on the primary blockchain, and detecting the faults, if they use the keys as of the block
  prior to the block being cosigned.

  We solve this by binding cosigns to a global cosigning session ID, which has a specific start
  block, and reading the keys from the start block. This means that so long as all validator sets
  agree on the start of a global cosigning session, they can verify all cosigns produced by that
  session, regardless of how it advances. Since agreeing on the start of a global cosigning session
  is mandated, there's no way to have validator sets follow two distinct global cosigning sessions
  without breaking the bounds of the cosigning protocol.
*/
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub(crate) struct GlobalCosigningSession {
  pub(crate) start_block_number: u64,
  pub(crate) cosigning_sets: Vec<ExternalValidatorSet>,
  pub(crate) keys: HashMap<ExternalNetworkId, Public>,
  pub(crate) stakes: HashMap<ExternalNetworkId, u64>,
  pub(crate) total_stake: u64,
}
type GlobalCosigningSessionId = [u8; 32];
impl GlobalCosigningSession {
  pub(crate) fn id(mut cosigners: Vec<ExternalValidatorSet>) -> GlobalCosigningSessionId {
    cosigners.sort_by_key(|a| borsh::to_vec(a).unwrap());
    Blake2s256::digest(borsh::to_vec(&cosigners).unwrap()).into()
  }
}

/// If the block has events.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
enum HasEvents {
  /// The block had a notable event.
  ///
  /// This is a special case as blocks with key gen events change the keys used for cosigning, and
  /// accordingly must be cosigned before we advance past them.
  Notable,
  /// The block had an non-notable event justifying a cosign.
  NonNotable,
  /// The block didn't have an event justifying a cosign.
  No,
}

mod has_events_ord {
  use core::cmp::Ordering;
  use super::HasEvents;

  impl PartialOrd for HasEvents {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
      Some(self.cmp(other))
    }
  }
  impl Ord for HasEvents {
    /// A `cmp` based on the significance of the values.
    ///
    /// This is intended to allow using `a.max(b)` in order for the more-significant `HasEvents` to
    /// resolve as the final `HasEvents`.
    fn cmp(&self, other: &Self) -> Ordering {
      #[allow(clippy::match_same_arms)]
      match (self, other) {
        (HasEvents::Notable, HasEvents::Notable) |
        (HasEvents::NonNotable, HasEvents::NonNotable) |
        (HasEvents::No, HasEvents::No) => Ordering::Equal,
        (HasEvents::No, HasEvents::Notable | HasEvents::NonNotable) => Ordering::Less,
        (HasEvents::Notable | HasEvents::NonNotable, HasEvents::No) => Ordering::Greater,
        (HasEvents::NonNotable, HasEvents::Notable) => Ordering::Less,
        (HasEvents::Notable, HasEvents::NonNotable) => Ordering::Greater,
      }
    }
  }

  #[test]
  fn has_events_ord() {
    assert_eq!(HasEvents::Notable.cmp(&HasEvents::Notable), Ordering::Equal);
    assert_eq!(HasEvents::NonNotable.cmp(&HasEvents::NonNotable), Ordering::Equal);
    assert_eq!(HasEvents::No.cmp(&HasEvents::No), Ordering::Equal);

    assert!(HasEvents::No < HasEvents::NonNotable);
    assert!(HasEvents::No < HasEvents::Notable);
    assert!(HasEvents::NonNotable < HasEvents::Notable);

    assert!(HasEvents::Notable > HasEvents::NonNotable);
    assert!(HasEvents::Notable > HasEvents::No);
    assert!(HasEvents::NonNotable > HasEvents::No);
  }
}

create_db! {
  Cosign {
    // The following are populated by the intend task and used throughout the library

    // An index of Substrate blocks
    SubstrateBlockHash: (block_number: u64) -> BlockHash,
    // A mapping from a global cosigning session's ID to its relevant information.
    GlobalCosigningSessions:
      (global_cosigning_session: GlobalCosigningSessionId) -> GlobalCosigningSession,
    // The last block to have been cosigned by a global cosigning session.
    GlobalCosigningSessionsLastBlock: (global_cosigning_session: GlobalCosigningSessionId) -> u64,
    // The latest global cosigning session intended.
    //
    // This is distinct from the latest global cosigning session for which we've evaluated cosigns.
    LatestGlobalCosigningSessionIntended: () -> GlobalCosigningSessionId,

    // The following are managed by the `intake_cosign` function present in this file

    // The latest cosigned block for each network.
    //
    // This will only be populated with cosigns predating or during the most recent global session
    // to have its start cosigned.
    //
    // The global cosigning session changes upon a notable block, causing each session to have
    // exactly one notable block. All validator sets will explicitly produce a cosign for their
    // notable block, causing the latest cosigned block for a session to either be the global
    // session's notable cosigns or the network's latest cosigns.
    NetworksLatestCosignedBlockIntaken: (
      global_cosigning_session: GlobalCosigningSessionId,
      network: ExternalNetworkId
    ) -> SignedCosign,
    // Cosigns received for blocks not locally recognized as finalized.
    Faults: (global_cosigning_session: GlobalCosigningSessionId) -> Vec<SignedCosign>,
    // The global cosigning session which faulted.
    FaultedCosigningSession: () -> GlobalCosigningSessionId,
  }
}

/// An object usable to request notable cosigns for a block.
pub trait RequestNotableCosigns: 'static + Send + Sync {
  /// The error type which may be encountered when requesting notable cosigns.
  type Error: Debug;

  /// Request the notable cosigns for this global cosigning session.
  fn request_notable_cosigns(
    &self,
    global_cosigning_session: GlobalCosigningSessionId,
  ) -> impl Send + Future<Output = Result<(), Self::Error>>;
}

/// An error used to indicate the cosigning protocol has faulted.
#[derive(Debug)]
pub struct Faulted;

/// An error incurred while intaking a cosign.
#[derive(Debug)]
pub enum IntakeCosignError {
  /// Cosign is for a not-yet-indexed block
  NotYetIndexedBlock,
  /// A later cosign for this cosigner has already been handled
  StaleCosign,
  /// The cosign's global cosigning session isn't recognized
  UnrecognizedGlobalSession,
  /// The cosign is for a block before its global cosigning session starts
  BeforeGlobalSessionStart,
  /// The cosign is for a block after its global cosigning session ends
  AfterGlobalSessionEnd,
  /// The cosign's signing network wasn't a participant in this global cosigning session
  NonParticipatingNetwork,
  /// The cosign had an invalid signature
  InvalidSignature,
  /// The cosign is for a session which has yet to have its declaration block cosigned
  FutureGlobalSession,
}

impl IntakeCosignError {
  /// If this error is temporal to the local view
  pub fn temporal(&self) -> bool {
    match self {
      IntakeCosignError::NotYetIndexedBlock |
      IntakeCosignError::StaleCosign |
      IntakeCosignError::UnrecognizedGlobalSession |
      IntakeCosignError::FutureGlobalSession => true,
      IntakeCosignError::BeforeGlobalSessionStart |
      IntakeCosignError::AfterGlobalSessionEnd |
      IntakeCosignError::NonParticipatingNetwork |
      IntakeCosignError::InvalidSignature => false,
    }
  }
}

/// The interface to manage cosigning with.
pub struct Cosigning<D: Db> {
  db: D,
  #[cfg(test)]
  join_handles: Vec<JoinHandle<()>>,
}
#[cfg(test)]
impl<D: Db> Drop for Cosigning<D> {
  fn drop(&mut self) {
    for handle in self.join_handles.drain(..) {
      handle.abort();
    }
  }
}

impl<D: Db> Cosigning<D> {
  #[cfg(test)]
  /// Create a cosigning handle using an already-initialized database.
  ///
  /// This does not spawn any background tasks; use `Cosigning::spawn` for the full service.
  pub fn new(db: D) -> Self {
    Self {
      db,
      #[cfg(test)]
      join_handles: vec![],
    }
  }

  /// Spawn the tasks to intend and evaluate cosigns.
  ///
  /// The database specified must only be used with a singular instance of the Serai network, and
  /// only used once at any given time.
  #[cfg(not(test))]
  #[allow(clippy::cfg_not_test)]
  pub fn spawn<R: RequestNotableCosigns>(
    db: D,
    serai: Arc<Serai>,
    request: R,
    tasks_to_run_upon_cosigning_blocks: Vec<TaskHandle>,
  ) -> Self {
    let (intend_task, intend_task_handle) = Task::new();
    // Forget the intend task handle, as dropping the handle would stop the task
    // keeps all cosign tasks running in the background
    core::mem::forget(intend_task_handle);

    let (evaluator_task, evaluator_task_handle) = Task::new();
    let (delay_task, delay_task_handle) = Task::new();
    tokio::spawn(
      (intend::CosignIntendTask { db: db.clone(), serai })
        .continually_run(intend_task, vec![evaluator_task_handle]),
    );
    tokio::spawn(
      (evaluator::CosignEvaluatorTask {
        db: db.clone(),
        request,
        last_request_for_cosigns: Instant::now(),
      })
      .continually_run(evaluator_task, vec![delay_task_handle]),
    );
    tokio::spawn(
      (delay::CosignDelayTask { db: db.clone() })
        .continually_run(delay_task, tasks_to_run_upon_cosigning_blocks),
    );

    Self { db }
  }

  /// Test-only variant of `spawn` that accepts a `test_label` for log identification.
  #[cfg(test)]
  pub fn spawn_with_handles<R: RequestNotableCosigns>(
    db: D,
    serai: Arc<Serai>,
    request: R,
    tasks_to_run_upon_cosigning_blocks: Vec<TaskHandle>,
  ) -> Self {
    let (intend_task, intend_task_handle) = Task::new();
    core::mem::forget(intend_task_handle);

    let (evaluator_task, evaluator_task_handle) = Task::new();
    let (delay_task, delay_task_handle) = Task::new();
    let join_handles = vec![
      tokio::spawn(
        (intend::CosignIntendTask { db: db.clone(), serai })
          .continually_run(intend_task, vec![evaluator_task_handle]),
      ),
      tokio::spawn(
        (evaluator::CosignEvaluatorTask {
          db: db.clone(),
          request,
          last_request_for_cosigns: Instant::now(),
        })
        .continually_run(evaluator_task, vec![delay_task_handle]),
      ),
      tokio::spawn(
        (delay::CosignDelayTask { db: db.clone() })
          .continually_run(delay_task, tasks_to_run_upon_cosigning_blocks),
      ),
    ];

    Self { db, join_handles }
  }

  /// Try to get the latest cosigned block number.
  /// Returns an `Err(Faulted)` if a faulted cosigning session exists.
  pub fn latest_cosigned_block_number(getter: &impl Get) -> Result<Option<u64>, Faulted> {
    if FaultedCosigningSession::get(getter).is_some() {
      Err(Faulted)?;
    }

    Ok(LatestCosignedBlockNumber::get(getter))
  }

  /// Try to fetch a cosigned Substrate block's hash by its block number.
  /// Returns an `Err(Faulted)` if a faulted cosigning session exists.
  /// Returns `None` if the block by number has not been cosigned yet.
  pub fn get_cosigned_blocks_hash(
    getter: &impl Get,
    block_number: u64,
  ) -> Result<Option<BlockHash>, Faulted> {
    let Some(latest) = Self::latest_cosigned_block_number(getter)? else {
      return Ok(None);
    };
    if block_number > latest {
      return Ok(None);
    }

    Ok(Some(
      SubstrateBlockHash::get(getter, block_number)
        .unwrap_or_else(|| panic!("cosigned the block {block_number} but didn't index it")),
    ))
  }

  /// Fetch notable cosigns for every network of a global cosigning session,
  /// in order to respond to requests.
  ///
  /// If this session hasn't produced any notable cosigns, this will return the latest
  /// cosigns for this session.
  pub fn all_networks_notable_or_latest_cosigns(
    getter: &impl Get,
    global_cosigning_session: GlobalCosigningSessionId,
  ) -> Vec<SignedCosign> {
    ExternalNetworkId::all()
      .filter_map(|network| {
        NetworksLatestCosignedBlockIntaken::get(getter, global_cosigning_session, network)
      })
      .collect()
  }

  /// The cosigns to rebroadcast every `BROADCAST_FREQUENCY` seconds.
  ///
  /// This will be the most recent cosigns in case the initial broadcast failed, or the faulty
  /// cosigns in case of a fault, in order to induce identification of the fault by others.
  pub fn cosigns_to_rebroadcast(&self) -> Vec<SignedCosign> {
    if let Some(existing_faulted_cosigning_session) = FaultedCosigningSession::get(&self.db) {
      let mut cosigns =
        Faults::get(&self.db, existing_faulted_cosigning_session).expect("faulted with no faults");
      // Also include all of our recognized-as-honest cosigns in an attempt to induce fault
      // identification in those who see the faulty cosigns as honest
      cosigns.extend(
        Self::all_networks_notable_or_latest_cosigns(&self.db, existing_faulted_cosigning_session)
          .into_iter()
          .filter(|c| c.cosign.global_cosigning_session == existing_faulted_cosigning_session),
      );

      return cosigns;
    }

    if let Some(current_global_cosigning_session_evaluating) =
      evaluator::current_global_cosigning_session_evaluating(&self.db)
    {
      return Self::all_networks_notable_or_latest_cosigns(
        &self.db,
        current_global_cosigning_session_evaluating,
      );
    }

    vec![]
  }

  /// Try to intake a cosign, or fails with [`IntakeCosignError`].
  //
  // Takes `&mut self` as this should only be called once at any given moment.
  pub fn intake_cosign(&mut self, signed_cosign: &SignedCosign) -> Result<(), IntakeCosignError> {
    let cosign = &signed_cosign.cosign;
    let network_for_cosign = cosign.cosigner;

    // Check our indexed blockchain includes a block with this block number
    let Some(indexed_block_hash) = SubstrateBlockHash::get(&self.db, cosign.block_number) else {
      Err(IntakeCosignError::NotYetIndexedBlock)?
    };
    let is_cosign_faulty = cosign.block_hash != indexed_block_hash;

    // Check this isn't a dated cosign within its session (as it would be if rebroadcasted)
    if !is_cosign_faulty {
      if let Some(networks_latest_cosigned_block) = NetworksLatestCosignedBlockIntaken::get(
        &self.db,
        cosign.global_cosigning_session,
        network_for_cosign,
      ) {
        if networks_latest_cosigned_block.cosign.block_number >= cosign.block_number {
          Err(IntakeCosignError::StaleCosign)?;
        }
      }
    }

    let Some(global_cosigning_session_for_cosign) =
      GlobalCosigningSessions::get(&self.db, cosign.global_cosigning_session)
    else {
      Err(IntakeCosignError::UnrecognizedGlobalSession)?
    };

    // Check the cosigned block number is in range to the global cosigning session
    if cosign.block_number < global_cosigning_session_for_cosign.start_block_number {
      // Cosign is for a block predating the global cosigning session
      Err(IntakeCosignError::BeforeGlobalSessionStart)?;
    }
    if !is_cosign_faulty {
      // This prevents a malicious validator set, on the same chain, from producing a cosign after
      // their final block, replacing their notable cosign
      if let Some(last_block) =
        GlobalCosigningSessionsLastBlock::get(&self.db, cosign.global_cosigning_session)
      {
        if cosign.block_number > last_block {
          // Cosign is for a block after the last block this session should have signed
          Err(IntakeCosignError::AfterGlobalSessionEnd)?;
        }
      }
    }

    // Check the cosign's signature
    {
      let key = *global_cosigning_session_for_cosign
        .keys
        .get(&network_for_cosign)
        .ok_or(IntakeCosignError::NonParticipatingNetwork)?;
      if !signed_cosign.verify_signature(key) {
        Err(IntakeCosignError::InvalidSignature)?;
      }
    }

    // Since we verified this cosign's signature, and have a chain valid and sufficiently long,
    // handle the cosign

    let mut txn = self.db.txn();

    if !is_cosign_faulty {
      // If this is for a future session, we don't acknowledge this cosign at this time
      let latest_cosigned_block_number = LatestCosignedBlockNumber::get(&txn).unwrap_or(0);
      // This session starts the block *after* its declaration, so we want to check if the
      // block declaring it was cosigned
      if (global_cosigning_session_for_cosign.start_block_number - 1) > latest_cosigned_block_number
      {
        Err(IntakeCosignError::FutureGlobalSession)?;
      }

      // This is safe as it's in-range and newer, as prior checked since it isn't faulty
      NetworksLatestCosignedBlockIntaken::set(
        &mut txn,
        cosign.global_cosigning_session,
        network_for_cosign,
        signed_cosign,
      );
    } else {
      let mut existing_global_cosigning_sessions_faults =
        Faults::get(&txn, cosign.global_cosigning_session).unwrap_or(vec![]);

      let session_has_prior_network_faults = existing_global_cosigning_sessions_faults
        .iter()
        .any(|cosign| cosign.cosign.cosigner == network_for_cosign);

      // Only handle this as a fault if this set wasn't prior faulty
      if !session_has_prior_network_faults {
        existing_global_cosigning_sessions_faults.push(signed_cosign.clone());

        Faults::set(
          &mut txn,
          cosign.global_cosigning_session,
          &existing_global_cosigning_sessions_faults,
        );

        let mut weight_cosigned = 0;
        for fault in &existing_global_cosigning_sessions_faults {
          let stake = global_cosigning_session_for_cosign
            .stakes
            .get(&fault.cosign.cosigner)
            .expect("cosigner with recognized key didn't have a stake entry saved");
          weight_cosigned += stake;
        }

        // Check if the sum weight means a fault has occurred
        if weight_cosigned >=
          cosign_fault_threshold(global_cosigning_session_for_cosign.total_stake)
        {
          FaultedCosigningSession::set(&mut txn, &cosign.global_cosigning_session);
        }
      }
    }

    txn.commit();
    Ok(())
  }

  /// Receive intended cosigns to produce for this ExternalValidatorSet.
  ///
  /// All cosigns intended, up to and including the next notable cosign, are returned.
  ///
  /// This will drain the internal channel and not re-yield these intentions again.
  pub fn all_intended_cosigns_for_network(
    txn: &mut impl DbTxn,
    set: ExternalValidatorSet,
  ) -> Vec<CosignIntent> {
    let mut intended_cosigns: Vec<CosignIntent> = vec![];
    // While we have yet to find a notable cosign...
    while !intended_cosigns.last().map(|cosign| cosign.notable).unwrap_or(false) {
      let Some(intent) = intend::NetworksIntendedCosigns::try_recv(txn, set) else { break };
      intended_cosigns.push(intent);
    }
    intended_cosigns
  }
}
