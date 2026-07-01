//! Canonical events, which must be handled by every validator,
//! regardless of the sets they're present in.
//!
//! Depends on cosigned blocks, on halt does not send new messages to the processor.
use core::future::Future;
use std::sync::Arc;

use serai_client_serai::{
  abi::{
    self, primitives::validator_sets::Session, primitives::network_id::ExternalNetworkId,
    validator_sets::ReportedSlashes,
  },
  Serai, Events,
};

use messages::substrate::{InInstructionResult, ExecutedBatch, CoordinatorMessage};

use serai_db::*;
use serai_task::{ContinuallyRan, FuturesRangeProcessor};

use serai_cosign::Cosigning;

create_db!(
  CoordinatorSubstrateCanonical {
    ScanCanonicalBlocksFrom: () -> u64,
    // Tracks the highest batch ID indexed per network.
    NetworksCanonicalLastIndexedBatchId: (network: ExternalNetworkId) -> u32,
    // Tracks sessions for which we've seen SlashesReported (either from a real on-chain
    // event or a shim). To enable detection of missing reports.
    SessionsCanonicalSlashesReported: (network: ExternalNetworkId, session: Session) -> (),
  }
);

/// These are all the events which generate canonical messages
pub struct CanonicalEvents {
  time: u64,
  events: Events,
}

/// The event stream for canonical events.
pub struct CanonicalEventStream<D: Db> {
  db: D,
  serai: Arc<Serai>,
}

impl<D: Db> CanonicalEventStream<D> {
  /// Create a new canonical event stream.
  ///
  /// Only one of these may exist over the provided database.
  pub fn new(db: D, serai: Arc<Serai>) -> Self {
    Self { db, serai }
  }
}

impl<D: Db> ContinuallyRan for CanonicalEventStream<D> {
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let Some(latest_cosigned_block_number) =
        Cosigning::<D>::latest_cosigned_block_number(&self.db)
          // Errors if Faulted session exists and keeps re-trying this task
          // protocol will be halted not able to progress
          .map_err(|e| format!("Error getting latest cosigned block number: {e:?}"))?
      else {
        return Ok(false);
      };

      let start_scan_block_number = ScanCanonicalBlocksFrom::get(&self.db).unwrap_or(0);
      self.process_range(start_scan_block_number, latest_cosigned_block_number).await
    }
  }
}

impl<D: Db> FuturesRangeProcessor for CanonicalEventStream<D> {
  type Item = CanonicalEvents;
  const ITEMS_TO_PROCESS_AT_ONCE: u64 = 10;

  fn fetch_item(
    &self,
    block_number: u64,
  ) -> impl Send + 'static + Future<Output = Result<(u64, Self::Item), Self::Error>> {
    let db = self.db.clone();
    let serai = self.serai.clone();
    async move {
      let block_hash = Cosigning::<D>::get_cosigned_blocks_hash(&db, block_number);
      let block_hash = match block_hash {
        Ok(Some(block_hash)) => block_hash,
        Ok(None) => {
          panic!(
            "iterating to latest cosigned block but couldn't get \
             cosigned block number {block_number}"
          )
        }
        Err(serai_cosign::Faulted) => return Err("cosigning process faulted".to_owned()),
      };

      let serai_block = serai
        .block(block_hash)
        .await
        .map_err(|e| format!("RPC error fetching block #{block_hash}: {e}"))?
        .unwrap_or_else(|| {
          // If latest_cosigned_block_number returned this block number
          // as cosigned and we iterated to it then it must exist on serai
          panic!(
            "Serai node didn't have block #{block_number} which should've been finalized and \
             cosigned"
          )
        });

      let events = serai
        .events(block_hash)
        .await
        .map_err(|e| format!("RPC error fetching block events #{block_hash}: {e}"))?;

      // We use time in seconds, not milliseconds, here
      let time = serai_block.header.unix_time_in_millis() / 1000;
      Ok((block_number, CanonicalEvents { time, events }))
    }
  }

  fn process_item(&mut self, block_number: u64, block: Self::Item) -> Result<(), Self::Error> {
    let mut txn = self.db.txn();

    let validator_sets_events = block.events.validator_sets();

    // First, handle declarations of the latest set
    // shims a slashes reported event if not arrived in a timely manner, then
    // for the latest set sends message for processor acknowledgement to handle it
    for set_keys in validator_sets_events.set_keys_events().cloned() {
      let abi::validator_sets::Event::SetKeys { set, key_pair } = set_keys else {
        unreachable!("`SetKeys` event wasn't a `SetKeys` event: {set_keys:?}");
      };

      // When session #n starts, session #(n-2)'s slash report should have been published (or
      // shimmed). If we haven't already sent SlashesReported for #n-2, shim it now.
      if let Some(historical_session) = set.session.0.checked_sub(2) {
        let historical_session = Session(historical_session);
        if SessionsCanonicalSlashesReported::get(&txn, set.network, historical_session).is_none() {
          crate::Canonical::send(
            &mut txn,
            set.network,
            &CoordinatorMessage::SlashesReported { session: historical_session },
          );
          SessionsCanonicalSlashesReported::set(&mut txn, set.network, historical_session, &());
        }
      }

      crate::Canonical::send(
        &mut txn,
        set.network,
        &CoordinatorMessage::SetKeys { serai_time: block.time, session: set.session, key_pair },
      );
    }

    // Second, handle slashes reported events in the block
    // sends message for processor acknowledgement of session retiry for it to handle
    for slash_report in validator_sets_events.slashes_events().cloned() {
      let abi::validator_sets::Event::Slashes(reported_slashes) = slash_report else {
        unreachable!("`Slashes` event wasn't a `Slashes` event: {slash_report:?}");
      };
      match reported_slashes {
        // We only coordinate over external networks
        ReportedSlashes::SeraiValidator(_) => {}
        ReportedSlashes::ExternalValidatorSet(set) => {
          // Only send if we haven't already sent SlashesReported for this session
          // (either from a prior real event or a shim)
          if SessionsCanonicalSlashesReported::get(&txn, set.network, set.session).is_none() {
            crate::Canonical::send(
              &mut txn,
              set.network,
              &CoordinatorMessage::SlashesReported { session: set.session },
            );
            SessionsCanonicalSlashesReported::set(&mut txn, set.network, set.session, &());
          }
        }
      }
    }

    // Third, handle coins related events
    // sends a single `Block` message for the processor to handle the events, if they exist
    for outer_network in ExternalNetworkId::all() {
      let mut networks_batch = None;
      for i_batch in block.events.in_instructions().batch_events() {
        // Only irrefutable as this is the only member of the enum at this time
        #[expect(irrefutable_let_patterns)]
        let abi::in_instructions::Event::Batch {
          network: i_batch_network,
          publishing_session,
          id,
          external_network_block_hash,
          in_instructions_hash,
          in_instruction_results,
        } = i_batch
        else {
          unreachable!("Batch event wasn't a Batch event: {i_batch:?}");
        };

        if outer_network == *i_batch_network {
          // Consensus invariant, should never happen
          assert!(
            networks_batch.is_none(),
            "Serai block had multiple batches for the same network"
          );

          networks_batch =
            Some(ExecutedBatch {
              id: *id,
              publisher: *publishing_session,
              external_network_block_hash: external_network_block_hash.0,
              in_instructions_hash: *in_instructions_hash,
              in_instruction_results: in_instruction_results
                .iter()
                .map(|bit| {
                  if *bit {
                    InInstructionResult::Succeeded
                  } else {
                    InInstructionResult::Failed
                  }
                })
                .collect(),
            });

          assert_eq!(
            NetworksCanonicalLastIndexedBatchId::get(&txn, outer_network),
            id.checked_sub(1),
            "next batch from Serai's ID was not an increment of the last indexed batch's ID"
          );
          NetworksCanonicalLastIndexedBatchId::set(&mut txn, outer_network, id);
        }
      }

      let mut networks_burns = vec![];
      for i_burn in block.events.coins().burn_with_instruction_events() {
        let abi::coins::Event::BurnWithInstruction { from: _, instruction: i_burn_instruction } =
          &i_burn
        else {
          unreachable!("BurnWithInstruction event wasn't a BurnWithInstruction event: {i_burn:?}")
        };
        if i_burn_instruction.balance.coin.network() == outer_network {
          networks_burns.push(i_burn_instruction.clone());
        }
      }

      if networks_batch.is_some() || !networks_burns.is_empty() {
        crate::Canonical::send(
          &mut txn,
          outer_network,
          &CoordinatorMessage::Block {
            serai_block_number: block_number,
            batch: networks_batch,
            burns: networks_burns,
          },
        );
      }
    }

    ScanCanonicalBlocksFrom::set(&mut txn, &(block_number + 1));
    txn.commit();
    Ok(())
  }
}

pub(crate) fn last_indexed_batch_id(getter: &impl Get, network: ExternalNetworkId) -> Option<u32> {
  NetworksCanonicalLastIndexedBatchId::get(getter, network)
}
