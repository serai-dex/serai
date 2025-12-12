use core::future::Future;
use std::sync::Arc;

use futures::stream::{StreamExt, FuturesOrdered};

use serai_client_serai::{
  abi::{self, primitives::network_id::ExternalNetworkId},
  Serai,
};

use messages::substrate::{InInstructionResult, ExecutedBatch, CoordinatorMessage};

use serai_db::*;
use serai_task::ContinuallyRan;

use serai_cosign::Cosigning;

create_db!(
  CoordinatorSubstrateCanonical {
    NextBlock: () -> u64,
    LastIndexedBatchId: (network: ExternalNetworkId) -> u32,
  }
);

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
      let next_block = NextBlock::get(&self.db).unwrap_or(0);
      let latest_finalized_block =
        Cosigning::<D>::latest_cosigned_block_number(&self.db).map_err(|e| format!("{e:?}"))?;

      // These are all the events which generate canonical messages
      struct CanonicalEvents {
        time: u64,
        set_keys_events: Vec<abi::validator_sets::Event>,
        slash_report_events: Vec<abi::validator_sets::Event>,
        batch_events: Vec<abi::in_instructions::Event>,
        burn_events: Vec<abi::coins::Event>,
      }

      // For a cosigned block, fetch all relevant events
      let scan = {
        let db = self.db.clone();
        let serai = &self.serai;
        move |block_number| {
          let block_hash = Cosigning::<D>::cosigned_block(&db, block_number);

          async move {
            let block_hash = match block_hash {
              Ok(Some(block_hash)) => block_hash,
              Ok(None) => {
                panic!("iterating to latest cosigned block but couldn't get cosigned block")
              }
              Err(serai_cosign::Faulted) => return Err("cosigning process faulted".to_owned()),
            };
            let events = serai.events(block_hash).await.map_err(|e| format!("{e}"))?;
            let set_keys_events = events.validator_sets().set_keys_events().cloned().collect();
            let slash_report_events =
              events.validator_sets().slash_report_events().cloned().collect();
            let batch_events = events.in_instructions().batch_events().cloned().collect();
            let burn_events = events.coins().burn_with_instruction_events().cloned().collect();
            let Some(block) = serai.block(block_hash).await.map_err(|e| format!("{e:?}"))? else {
              Err(format!("Serai node didn't have cosigned block #{block_number}"))?
            };

            // We use time in seconds, not milliseconds, here
            let time = block.header.unix_time_in_millis() / 1000;
            Ok((
              block_number,
              CanonicalEvents {
                time,
                set_keys_events,
                slash_report_events,
                batch_events,
                burn_events,
              },
            ))
          }
        }
      };

      // Sync the next set of upcoming blocks all at once to minimize latency
      const BLOCKS_TO_SYNC_AT_ONCE: u64 = 10;
      // FuturesOrdered can be bad practice due to potentially causing tiemouts if it isn't
      // sufficiently polled. Considering our processing loop is minimal and it does poll this,
      // it's fine.
      let mut set = FuturesOrdered::new();
      for block_number in
        next_block ..= latest_finalized_block.min(next_block + BLOCKS_TO_SYNC_AT_ONCE)
      {
        set.push_back(scan(block_number));
      }

      for block_number in next_block ..= latest_finalized_block {
        // Get the next block in our queue
        let (popped_block_number, block) = set.next().await.unwrap()?;
        assert_eq!(block_number, popped_block_number);
        // Re-populate the queue
        if (block_number + BLOCKS_TO_SYNC_AT_ONCE) <= latest_finalized_block {
          set.push_back(scan(block_number + BLOCKS_TO_SYNC_AT_ONCE));
        }

        let mut txn = self.db.txn();

        for set_keys in block.set_keys_events {
          let abi::validator_sets::Event::SetKeys { set, key_pair } = &set_keys else {
            panic!("`SetKeys` event wasn't a `SetKeys` event: {set_keys:?}");
          };
          crate::Canonical::send(
            &mut txn,
            set.network,
            &CoordinatorMessage::SetKeys {
              serai_time: block.time,
              session: set.session,
              key_pair: key_pair.clone(),
            },
          );
        }

        for slash_report in block.slash_report_events {
          let abi::validator_sets::Event::SlashReport { set } = &slash_report else {
            panic!("`SlashReport` event wasn't a `SlashReport` event: {slash_report:?}");
          };
          crate::Canonical::send(
            &mut txn,
            set.network,
            &CoordinatorMessage::SlashesReported { session: set.session },
          );
        }

        for network in ExternalNetworkId::all() {
          let mut batch = None;
          for this_batch in &block.batch_events {
            // Only irrefutable as this is the only member of the enum at this time
            #[expect(irrefutable_let_patterns)]
            let abi::in_instructions::Event::Batch {
              network: batch_network,
              publishing_session,
              id,
              external_network_block_hash,
              in_instructions_hash,
              in_instruction_results,
            } = this_batch
            else {
              panic!("Batch event wasn't a Batch event: {this_batch:?}");
            };
            if network == *batch_network {
              if batch.is_some() {
                Err("Serai block had multiple batches for the same network".to_owned())?;
              }
              batch = Some(ExecutedBatch {
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
                LastIndexedBatchId::get(&txn, network),
                id.checked_sub(1),
                "next batch from Serai's ID was not an increment of the last indexed batch's ID"
              );
              LastIndexedBatchId::set(&mut txn, network, id);
            }
          }

          let mut burns = vec![];
          for burn in &block.burn_events {
            let abi::coins::Event::BurnWithInstruction { from: _, instruction } = &burn else {
              panic!("BurnWithInstruction event wasn't a BurnWithInstruction event: {burn:?}");
            };
            if instruction.balance.coin.network() == network {
              burns.push(instruction.clone());
            }
          }

          crate::Canonical::send(
            &mut txn,
            network,
            &CoordinatorMessage::Block { serai_block_number: block_number, batch, burns },
          );
        }

        txn.commit();
      }

      Ok(next_block <= latest_finalized_block)
    }
  }
}

pub(crate) fn last_indexed_batch_id(txn: &impl DbTxn, network: ExternalNetworkId) -> Option<u32> {
  LastIndexedBatchId::get(txn, network)
}
