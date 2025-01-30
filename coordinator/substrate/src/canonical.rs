use core::future::Future;
use std::sync::Arc;

use futures::stream::{StreamExt, FuturesOrdered};

use serai_client::{validator_sets::primitives::ExternalValidatorSet, Serai};

use messages::substrate::{InInstructionResult, ExecutedBatch, CoordinatorMessage};

use serai_db::*;
use serai_task::ContinuallyRan;

use serai_cosign::Cosigning;

create_db!(
  CoordinatorSubstrateCanonical {
    NextBlock: () -> u64,
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
        key_gen_events: Vec<serai_client::validator_sets::ValidatorSetsEvent>,
        set_retired_events: Vec<serai_client::validator_sets::ValidatorSetsEvent>,
        batch_events: Vec<serai_client::in_instructions::InInstructionsEvent>,
        burn_events: Vec<serai_client::coins::CoinsEvent>,
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
              Err(serai_cosign::Faulted) => return Err("cosigning process faulted".to_string()),
            };
            let temporal_serai = serai.as_of(block_hash);
            let temporal_serai_validators = temporal_serai.validator_sets();
            let temporal_serai_instructions = temporal_serai.in_instructions();
            let temporal_serai_coins = temporal_serai.coins();

            let (block, key_gen_events, set_retired_events, batch_events, burn_events) =
              tokio::try_join!(
                serai.block(block_hash),
                temporal_serai_validators.key_gen_events(),
                temporal_serai_validators.set_retired_events(),
                temporal_serai_instructions.batch_events(),
                temporal_serai_coins.burn_with_instruction_events(),
              )
              .map_err(|e| format!("{e:?}"))?;
            let Some(block) = block else {
              Err(format!("Serai node didn't have cosigned block #{block_number}"))?
            };

            let time = if block_number == 0 {
              block.time().unwrap_or(0)
            } else {
              // Serai's block time is in milliseconds
              block
                .time()
                .ok_or_else(|| "non-genesis Serai block didn't have a time".to_string())? /
                1000
            };

            Ok((
              block_number,
              CanonicalEvents {
                time,
                key_gen_events,
                set_retired_events,
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

        for key_gen in block.key_gen_events {
          let serai_client::validator_sets::ValidatorSetsEvent::KeyGen { set, key_pair } = &key_gen
          else {
            panic!("KeyGen event wasn't a KeyGen event: {key_gen:?}");
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

        for set_retired in block.set_retired_events {
          let serai_client::validator_sets::ValidatorSetsEvent::SetRetired { set } = &set_retired
          else {
            panic!("SetRetired event wasn't a SetRetired event: {set_retired:?}");
          };
          let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };
          crate::Canonical::send(
            &mut txn,
            set.network,
            &CoordinatorMessage::SlashesReported { session: set.session },
          );
        }

        for network in serai_client::primitives::EXTERNAL_NETWORKS {
          let mut batch = None;
          for this_batch in &block.batch_events {
            let serai_client::in_instructions::InInstructionsEvent::Batch {
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
                Err("Serai block had multiple batches for the same network".to_string())?;
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
            }
          }

          let mut burns = vec![];
          for burn in &block.burn_events {
            let serai_client::coins::CoinsEvent::BurnWithInstruction { from: _, instruction } =
              &burn
            else {
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
