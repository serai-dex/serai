use core::future::Future;
use std::sync::Arc;

use futures::stream::{StreamExt, FuturesOrdered};

use serai_client::{
  primitives::{SeraiAddress, EmbeddedEllipticCurve},
  validator_sets::primitives::{MAX_KEY_SHARES_PER_SET, ExternalValidatorSet},
  Serai,
};

use serai_db::*;
use serai_task::ContinuallyRan;

use serai_cosign::Cosigning;

use crate::NewSetInformation;

create_db!(
  CoordinatorSubstrateEphemeral {
    NextBlock: () -> u64,
  }
);

/// The event stream for ephemeral events.
pub struct EphemeralEventStream<D: Db> {
  db: D,
  serai: Arc<Serai>,
  validator: SeraiAddress,
}

impl<D: Db> EphemeralEventStream<D> {
  /// Create a new ephemeral event stream.
  ///
  /// Only one of these may exist over the provided database.
  pub fn new(db: D, serai: Arc<Serai>, validator: SeraiAddress) -> Self {
    Self { db, serai, validator }
  }
}

impl<D: Db> ContinuallyRan for EphemeralEventStream<D> {
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let next_block = NextBlock::get(&self.db).unwrap_or(0);
      let latest_finalized_block =
        Cosigning::<D>::latest_cosigned_block_number(&self.db).map_err(|e| format!("{e:?}"))?;

      // These are all the events which generate canonical messages
      struct EphemeralEvents {
        block_hash: [u8; 32],
        time: u64,
        new_set_events: Vec<serai_client::validator_sets::ValidatorSetsEvent>,
        accepted_handover_events: Vec<serai_client::validator_sets::ValidatorSetsEvent>,
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
            let (block, new_set_events, accepted_handover_events) = tokio::try_join!(
              serai.block(block_hash),
              temporal_serai_validators.new_set_events(),
              temporal_serai_validators.accepted_handover_events(),
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
              EphemeralEvents { block_hash, time, new_set_events, accepted_handover_events },
            ))
          }
        }
      };

      // Sync the next set of upcoming blocks all at once to minimize latency
      const BLOCKS_TO_SYNC_AT_ONCE: u64 = 50;
      // FuturesOrdered can be bad practice due to potentially causing tiemouts if it isn't
      // sufficiently polled. Our processing loop isn't minimal, itself making multiple requests,
      // but the loop body should only be executed a few times a week. It's better to get through
      // most blocks with this optimization, and have timeouts a few times a week, than not have
      // this at all.
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

        for new_set in block.new_set_events {
          let serai_client::validator_sets::ValidatorSetsEvent::NewSet { set } = &new_set else {
            panic!("NewSet event wasn't a NewSet event: {new_set:?}");
          };
          // We only coordinate over external networks
          let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };

          let serai = self.serai.as_of(block.block_hash);
          let serai = serai.validator_sets();
          let Some(validators) =
            serai.participants(set.network.into()).await.map_err(|e| format!("{e:?}"))?
          else {
            Err(format!(
              "block #{block_number} declared a new set but didn't have the participants"
            ))?
          };
          let validators = validators
            .into_iter()
            .map(|(validator, weight)| (SeraiAddress::from(validator), weight))
            .collect::<Vec<_>>();
          let in_set = validators.iter().any(|(validator, _)| *validator == self.validator);
          if in_set {
            if u16::try_from(validators.len()).is_err() {
              Err("more than u16::MAX validators sent")?;
            }

            let Ok(validators) = validators
              .into_iter()
              .map(|(validator, weight)| u16::try_from(weight).map(|weight| (validator, weight)))
              .collect::<Result<Vec<_>, _>>()
            else {
              Err("validator's weight exceeded u16::MAX".to_string())?
            };

            // Do the summation in u32 so we don't risk a u16 overflow
            let total_weight = validators.iter().map(|(_, weight)| u32::from(*weight)).sum::<u32>();
            if total_weight > u32::from(MAX_KEY_SHARES_PER_SET) {
              Err(format!(
                "{set:?} has {total_weight} key shares when the max is {MAX_KEY_SHARES_PER_SET}"
              ))?;
            }
            let total_weight = u16::try_from(total_weight).unwrap();

            // Fetch all of the validators' embedded elliptic curve keys
            let mut embedded_elliptic_curve_keys = FuturesOrdered::new();
            for (validator, _) in &validators {
              let validator = *validator;
              // try_join doesn't return a future so we need to wrap it in this additional async
              // block
              embedded_elliptic_curve_keys.push_back(async move {
                tokio::try_join!(
                  // One future to fetch the substrate embedded key
                  serai.embedded_elliptic_curve_key(
                    validator.into(),
                    EmbeddedEllipticCurve::Embedwards25519
                  ),
                  // One future to fetch the external embedded key, if there is a distinct curve
                  async {
                    // `embedded_elliptic_curves` is documented to have the second entry be the
                    // network-specific curve (if it exists and is distinct from Embedwards25519)
                    if let Some(curve) = set.network.embedded_elliptic_curves().get(1) {
                      serai.embedded_elliptic_curve_key(validator.into(), *curve).await.map(Some)
                    } else {
                      Ok(None)
                    }
                  }
                )
                .map(|(substrate_embedded_key, external_embedded_key)| {
                  (validator, substrate_embedded_key, external_embedded_key)
                })
              });
            }

            let mut evrf_public_keys = Vec::with_capacity(usize::from(total_weight));
            for (validator, weight) in &validators {
              let (future_validator, substrate_embedded_key, external_embedded_key) =
                embedded_elliptic_curve_keys.next().await.unwrap().map_err(|e| format!("{e:?}"))?;
              assert_eq!(*validator, future_validator);
              let external_embedded_key =
                external_embedded_key.unwrap_or(substrate_embedded_key.clone());
              match (substrate_embedded_key, external_embedded_key) {
                (Some(substrate_embedded_key), Some(external_embedded_key)) => {
                  let substrate_embedded_key = <[u8; 32]>::try_from(substrate_embedded_key)
                    .map_err(|_| "Embedwards25519 key wasn't 32 bytes".to_string())?;
                  for _ in 0 .. *weight {
                    evrf_public_keys.push((substrate_embedded_key, external_embedded_key.clone()));
                  }
                }
                _ => Err("NewSet with validator missing an embedded key".to_string())?,
              }
            }

            let mut new_set = NewSetInformation {
              set,
              serai_block: block.block_hash,
              declaration_time: block.time,
              // TODO: This should be inlined into the Processor's key gen code
              // It's legacy from when we removed participants from the key gen
              threshold: ((total_weight * 2) / 3) + 1,
              validators,
              evrf_public_keys,
              participant_indexes: Default::default(),
              participant_indexes_reverse_lookup: Default::default(),
            };
            // These aren't serialized, and we immediately serialize and drop this, so this isn't
            // necessary. It's just good practice not have this be dirty
            new_set.init_participant_indexes();
            crate::NewSet::send(&mut txn, &new_set);
          }
        }

        for accepted_handover in block.accepted_handover_events {
          let serai_client::validator_sets::ValidatorSetsEvent::AcceptedHandover { set } =
            &accepted_handover
          else {
            panic!("AcceptedHandover event wasn't a AcceptedHandover event: {accepted_handover:?}");
          };
          let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };
          crate::SignSlashReport::send(&mut txn, set);
        }

        txn.commit();
      }

      Ok(next_block <= latest_finalized_block)
    }
  }
}
