#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

use core::{fmt::Debug, future::Future};
use std::{sync::Arc, collections::HashMap, time::Instant};

use blake2::{Digest, Blake2s256};

use borsh::{BorshSerialize, BorshDeserialize};

use serai_client_serai::{
  abi::{
    primitives::{
      BlockHash, crypto::Public, network_id::ExternalNetworkId,
      validator_sets::ExternalValidatorSet,
    },
    Block,
  },
  Serai,
};

use serai_db::*;
use serai_task::*;

pub use serai_cosign_types::*;

/// The cosigns which are intended to be performed.
mod intend;
/// The evaluator of the cosigns.
mod evaluator;
/// The task to delay acknowledgement of the cosigns.
mod delay;
pub use delay::BROADCAST_FREQUENCY;
use delay::LatestCosignedBlockNumber;

/// A 'global session', defined as all validator sets used for cosigning at a given moment.
///
/// We evaluate cosign faults within a global session. This ensures even if cosigners cosign
/// distinct blocks at distinct positions within a global session, we still identify the faults.
/*
  There is the attack where a validator set is given an alternate blockchain with a key generation
  event at block #n, while most validator sets are given a blockchain with a key generation event
  at block number #(n+1). This prevents whoever has the alternate blockchain from verifying the
  cosigns on the primary blockchain, and detecting the faults, if they use the keys as of the block
  prior to the block being cosigned.

  We solve this by binding cosigns to a global session ID, which has a specific start block, and
  reading the keys from the start block. This means that so long as all validator sets agree on the
  start of a global session, they can verify all cosigns produced by that session, regardless of
  how it advances. Since agreeing on the start of a global session is mandated, there's no way to
  have validator sets follow two distinct global sessions without breaking the bounds of the
  cosigning protocol.
*/
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub(crate) struct GlobalSession {
  pub(crate) start_block_number: u64,
  pub(crate) sets: Vec<ExternalValidatorSet>,
  pub(crate) keys: HashMap<ExternalNetworkId, Public>,
  pub(crate) stakes: HashMap<ExternalNetworkId, u64>,
  pub(crate) total_stake: u64,
}
impl GlobalSession {
  fn id(mut cosigners: Vec<ExternalValidatorSet>) -> [u8; 32] {
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

create_db! {
  Cosign {
    // The following are populated by the intend task and used throughout the library

    // An index of Substrate blocks
    SubstrateBlockHash: (block_number: u64) -> BlockHash,
    // A mapping from a global session's ID to its relevant information.
    GlobalSessions: (global_session: [u8; 32]) -> GlobalSession,
    // The last block to be cosigned by a global session.
    GlobalSessionsLastBlock: (global_session: [u8; 32]) -> u64,
    // The latest global session intended.
    //
    // This is distinct from the latest global session for which we've evaluated the cosigns for.
    LatestGlobalSessionIntended: () -> [u8; 32],

    // The following are managed by the `intake_cosign` function present in this file

    // The latest cosigned block for each network.
    //
    // This will only be populated with cosigns predating or during the most recent global session
    // to have its start cosigned.
    //
    // The global session changes upon a notable block, causing each global session to have exactly
    // one notable block. All validator sets will explicitly produce a cosign for their notable
    // block, causing the latest cosigned block for a global session to either be the global
    // session's notable cosigns or the network's latest cosigns.
    NetworksLatestCosignedBlock: (
      global_session: [u8; 32],
      network: ExternalNetworkId
    ) -> SignedCosign,
    // Cosigns received for blocks not locally recognized as finalized.
    Faults: (global_session: [u8; 32]) -> Vec<SignedCosign>,
    // The global session which faulted.
    FaultedSession: () -> [u8; 32],
  }
}

/// An object usable to request notable cosigns for a block.
pub trait RequestNotableCosigns: 'static + Send {
  /// The error type which may be encountered when requesting notable cosigns.
  type Error: Debug;

  /// Request the notable cosigns for this global session.
  fn request_notable_cosigns(
    &self,
    global_session: [u8; 32],
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
  /// The cosign's global session isn't recognized
  UnrecognizedGlobalSession,
  /// The cosign is for a block before its global session starts
  BeforeGlobalSessionStart,
  /// The cosign is for a block after its global session ends
  AfterGlobalSessionEnd,
  /// The cosign's signing network wasn't a participant in this global session
  NonParticipatingNetwork,
  /// The cosign had an invalid signature
  InvalidSignature,
  /// The cosign is for a global session which has yet to have its declaration block cosigned
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
}
impl<D: Db> Cosigning<D> {
  /// Spawn the tasks to intend and evaluate cosigns.
  ///
  /// The database specified must only be used with a singular instance of the Serai network, and
  /// only used once at any given time.
  pub fn spawn<R: RequestNotableCosigns>(
    db: D,
    serai: Arc<Serai>,
    request: R,
    tasks_to_run_upon_cosigning: Vec<TaskHandle>,
  ) -> Self {
    let (intend_task, _intend_task_handle) = Task::new();
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
        .continually_run(delay_task, tasks_to_run_upon_cosigning),
    );
    Self { db }
  }

  /// The latest cosigned block number.
  pub fn latest_cosigned_block_number(getter: &impl Get) -> Result<u64, Faulted> {
    if FaultedSession::get(getter).is_some() {
      Err(Faulted)?;
    }

    Ok(LatestCosignedBlockNumber::get(getter).unwrap_or(0))
  }

  /// Fetch a cosigned Substrate block's hash by its block number.
  pub fn cosigned_block(
    getter: &impl Get,
    block_number: u64,
  ) -> Result<Option<BlockHash>, Faulted> {
    if block_number > Self::latest_cosigned_block_number(getter)? {
      return Ok(None);
    }

    Ok(Some(
      SubstrateBlockHash::get(getter, block_number).expect("cosigned block but didn't index it"),
    ))
  }

  /// Fetch the notable cosigns for a global session in order to respond to requests.
  ///
  /// If this global session hasn't produced any notable cosigns, this will return the latest
  /// cosigns for this session.
  pub fn notable_cosigns(getter: &impl Get, global_session: [u8; 32]) -> Vec<SignedCosign> {
    let mut cosigns = vec![];
    for network in ExternalNetworkId::all() {
      if let Some(cosign) = NetworksLatestCosignedBlock::get(getter, global_session, network) {
        cosigns.push(cosign);
      }
    }
    cosigns
  }

  /// The cosigns to rebroadcast every `BROADCAST_FREQUENCY` seconds.
  ///
  /// This will be the most recent cosigns, in case the initial broadcast failed, or the faulty
  /// cosigns, in case of a fault, to induce identification of the fault by others.
  pub fn cosigns_to_rebroadcast(&self) -> Vec<SignedCosign> {
    if let Some(faulted) = FaultedSession::get(&self.db) {
      let mut cosigns = Faults::get(&self.db, faulted).expect("faulted with no faults");
      // Also include all of our recognized-as-honest cosigns in an attempt to induce fault
      // identification in those who see the faulty cosigns as honest
      for network in ExternalNetworkId::all() {
        if let Some(cosign) = NetworksLatestCosignedBlock::get(&self.db, faulted, network) {
          if cosign.cosign.global_session == faulted {
            cosigns.push(cosign);
          }
        }
      }
      cosigns
    } else {
      let Some(global_session) = evaluator::currently_evaluated_global_session(&self.db) else {
        return vec![];
      };
      let mut cosigns = vec![];
      for network in ExternalNetworkId::all() {
        if let Some(cosign) = NetworksLatestCosignedBlock::get(&self.db, global_session, network) {
          cosigns.push(cosign);
        }
      }
      cosigns
    }
  }

  /// Intake a cosign.
  //
  // Takes `&mut self` as this should only be called once at any given moment.
  pub fn intake_cosign(&mut self, signed_cosign: &SignedCosign) -> Result<(), IntakeCosignError> {
    let cosign = &signed_cosign.cosign;
    let network = cosign.cosigner;

    // Check our indexed blockchain includes a block with this block number
    let Some(our_block_hash) = SubstrateBlockHash::get(&self.db, cosign.block_number) else {
      Err(IntakeCosignError::NotYetIndexedBlock)?
    };
    let faulty = cosign.block_hash != our_block_hash;

    // Check this isn't a dated cosign within its global session (as it would be if rebroadcasted)
    if !faulty {
      if let Some(existing) =
        NetworksLatestCosignedBlock::get(&self.db, cosign.global_session, network)
      {
        if existing.cosign.block_number >= cosign.block_number {
          Err(IntakeCosignError::StaleCosign)?;
        }
      }
    }

    let Some(global_session) = GlobalSessions::get(&self.db, cosign.global_session) else {
      Err(IntakeCosignError::UnrecognizedGlobalSession)?
    };

    // Check the cosigned block number is in range to the global session
    if cosign.block_number < global_session.start_block_number {
      // Cosign is for a block predating the global session
      Err(IntakeCosignError::BeforeGlobalSessionStart)?;
    }
    if !faulty {
      // This prevents a malicious validator set, on the same chain, from producing a cosign after
      // their final block, replacing their notable cosign
      if let Some(last_block) = GlobalSessionsLastBlock::get(&self.db, cosign.global_session) {
        if cosign.block_number > last_block {
          // Cosign is for a block after the last block this global session should have signed
          Err(IntakeCosignError::AfterGlobalSessionEnd)?;
        }
      }
    }

    // Check the cosign's signature
    {
      let key =
        *global_session.keys.get(&network).ok_or(IntakeCosignError::NonParticipatingNetwork)?;
      if !signed_cosign.verify_signature(key) {
        Err(IntakeCosignError::InvalidSignature)?;
      }
    }

    // Since we verified this cosign's signature, and have a chain sufficiently long, handle the
    // cosign

    let mut txn = self.db.txn();

    if !faulty {
      // If this is for a future global session, we don't acknowledge this cosign at this time
      let latest_cosigned_block_number = LatestCosignedBlockNumber::get(&txn).unwrap_or(0);
      // This global session starts the block *after* its declaration, so we want to check if the
      // block declaring it was cosigned
      if (global_session.start_block_number - 1) > latest_cosigned_block_number {
        drop(txn);
        return Err(IntakeCosignError::FutureGlobalSession);
      }

      // This is safe as it's in-range and newer, as prior checked since it isn't faulty
      NetworksLatestCosignedBlock::set(&mut txn, cosign.global_session, network, signed_cosign);
    } else {
      let mut faults = Faults::get(&txn, cosign.global_session).unwrap_or(vec![]);
      // Only handle this as a fault if this set wasn't prior faulty
      if !faults.iter().any(|cosign| cosign.cosign.cosigner == network) {
        faults.push(signed_cosign.clone());
        Faults::set(&mut txn, cosign.global_session, &faults);

        let mut weight_cosigned = 0;
        for fault in &faults {
          let stake = global_session
            .stakes
            .get(&fault.cosign.cosigner)
            .expect("cosigner with recognized key didn't have a stake entry saved");
          weight_cosigned += stake;
        }

        // Check if the sum weight means a fault has occurred
        if weight_cosigned >= ((global_session.total_stake * 17) / 100) {
          FaultedSession::set(&mut txn, &cosign.global_session);
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
  pub fn intended_cosigns(txn: &mut impl DbTxn, set: ExternalValidatorSet) -> Vec<CosignIntent> {
    let mut res: Vec<CosignIntent> = vec![];
    // While we have yet to find a notable cosign...
    while !res.last().map(|cosign| cosign.notable).unwrap_or(false) {
      let Some(intent) = intend::IntendedCosigns::try_recv(txn, set) else { break };
      res.push(intent);
    }
    res
  }
}
