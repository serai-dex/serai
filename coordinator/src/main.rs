use core::ops::Deref;
use std::{
  sync::{OnceLock, Arc},
  time::Duration,
  collections::{VecDeque, HashSet, HashMap},
};

use zeroize::{Zeroize, Zeroizing};
use rand_core::OsRng;

use ciphersuite::{
  group::ff::{Field, PrimeField},
  Ciphersuite, Ristretto,
};
use schnorr::SchnorrSignature;
use frost::Participant;

use serai_db::{DbTxn, Db};

use scale::Encode;
use borsh::BorshSerialize;
use serai_client::{
  primitives::NetworkId,
  validator_sets::primitives::{Session, ValidatorSet, KeyPair},
  Public, Serai, SeraiInInstructions,
};

use message_queue::{Service, client::MessageQueue};

use tokio::{
  sync::{Mutex, RwLock, mpsc, broadcast},
  time::sleep,
};

use ::tributary::{ProvidedError, TransactionKind, TransactionTrait, Block, Tributary};

mod tributary;
use crate::tributary::{
  TributarySpec, Label, SignData, Transaction, scanner::RecognizedIdType, PlanIds,
};

mod db;
use db::*;

mod p2p;
pub use p2p::*;

use processor_messages::{
  key_gen, sign,
  coordinator::{self, SubstrateSignableId},
  ProcessorMessage,
};

pub mod processors;
use processors::Processors;

mod substrate;
use substrate::CosignTransactions;

mod cosign_evaluator;
use cosign_evaluator::CosignEvaluator;

#[cfg(test)]
pub mod tests;

#[derive(Clone)]
pub struct ActiveTributary<D: Db, P: P2p> {
  pub spec: TributarySpec,
  pub tributary: Arc<Tributary<D, Transaction, P>>,
}

#[derive(Clone)]
pub enum TributaryEvent<D: Db, P: P2p> {
  NewTributary(ActiveTributary<D, P>),
  TributaryRetired(ValidatorSet),
}

// Creates a new tributary and sends it to all listeners.
async fn add_tributary<D: Db, Pro: Processors, P: P2p>(
  db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  processors: &Pro,
  p2p: P,
  tributaries: &broadcast::Sender<TributaryEvent<D, P>>,
  spec: TributarySpec,
) {
  if RetiredTributaryDb::get(&db, spec.set()).is_some() {
    log::info!("not adding tributary {:?} since it's been retired", spec.set());
  }

  log::info!("adding tributary {:?}", spec.set());

  let tributary = Tributary::<_, Transaction, _>::new(
    // TODO2: Use a db on a distinct volume to protect against DoS attacks
    // TODO2: Delete said db once the Tributary is dropped
    db,
    spec.genesis(),
    spec.start_time(),
    key.clone(),
    spec.validators(),
    p2p,
  )
  .await
  .unwrap();

  // Trigger a DKG for the newly added Tributary
  // If we're rebooting, we'll re-fire this message
  // This is safe due to the message-queue deduplicating based off the intent system
  let set = spec.set();
  let our_i = spec
    .i(&[], Ristretto::generator() * key.deref())
    .expect("adding a tributary for a set we aren't in set for");
  processors
    .send(
      set.network,
      processor_messages::key_gen::CoordinatorMessage::GenerateKey {
        id: processor_messages::key_gen::KeyGenId { session: set.session, attempt: 0 },
        params: frost::ThresholdParams::new(spec.t(), spec.n(&[]), our_i.start).unwrap(),
        shares: u16::from(our_i.end) - u16::from(our_i.start),
      },
    )
    .await;

  tributaries
    .send(TributaryEvent::NewTributary(ActiveTributary { spec, tributary: Arc::new(tributary) }))
    .map_err(|_| "all ActiveTributary recipients closed")
    .unwrap();
}

// TODO: Find a better pattern for this
static HANDOVER_VERIFY_QUEUE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

#[allow(clippy::too_many_arguments)]
async fn handle_processor_message<D: Db, P: P2p>(
  db: &mut D,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: &Serai,
  p2p: &P,
  cosign_channel: &mpsc::UnboundedSender<CosignedBlock>,
  tributaries: &HashMap<Session, ActiveTributary<D, P>>,
  network: NetworkId,
  msg: &processors::Message,
) -> bool {
  #[allow(clippy::nonminimal_bool)]
  if let Some(already_handled) = HandledMessageDb::get(db, msg.network) {
    assert!(!(already_handled > msg.id));
    assert!((already_handled == msg.id) || (already_handled == msg.id - 1));
    if already_handled == msg.id {
      return true;
    }
  } else {
    assert_eq!(msg.id, 0);
  }

  let _hvq_lock = HANDOVER_VERIFY_QUEUE_LOCK.get_or_init(|| Mutex::new(())).lock().await;
  let mut txn = db.txn();

  let mut relevant_tributary = match &msg.msg {
    // We'll only receive these if we fired GenerateKey, which we'll only do if if we're
    // in-set, making the Tributary relevant
    ProcessorMessage::KeyGen(inner_msg) => match inner_msg {
      key_gen::ProcessorMessage::Commitments { id, .. } |
      key_gen::ProcessorMessage::InvalidCommitments { id, .. } |
      key_gen::ProcessorMessage::Shares { id, .. } |
      key_gen::ProcessorMessage::InvalidShare { id, .. } |
      key_gen::ProcessorMessage::GeneratedKeyPair { id, .. } |
      key_gen::ProcessorMessage::Blame { id, .. } => Some(id.session),
    },
    ProcessorMessage::Sign(inner_msg) => match inner_msg {
      // We'll only receive InvalidParticipant/Preprocess/Share if we're actively signing
      sign::ProcessorMessage::InvalidParticipant { id, .. } |
      sign::ProcessorMessage::Preprocess { id, .. } |
      sign::ProcessorMessage::Share { id, .. } => Some(id.session),
      // While the Processor's Scanner will always emit Completed, that's routed through the
      // Signer and only becomes a ProcessorMessage::Completed if the Signer is present and
      // confirms it
      sign::ProcessorMessage::Completed { session, .. } => Some(*session),
    },
    ProcessorMessage::Coordinator(inner_msg) => match inner_msg {
      // This is a special case as it's relevant to *all* Tributaries for this network we're
      // signing in
      // It doesn't return a Tributary to become `relevant_tributary` though
      coordinator::ProcessorMessage::SubstrateBlockAck { block, plans } => {
        // Get the sessions for these keys
        let sessions = plans
          .iter()
          .map(|plan| plan.session)
          .filter(|session| {
            RetiredTributaryDb::get(&txn, ValidatorSet { network, session: *session }).is_none()
          })
          .collect::<HashSet<_>>();

        // Ensure we have the Tributaries
        for session in &sessions {
          if !tributaries.contains_key(session) {
            return false;
          }
        }

        for session in sessions {
          let tributary = &tributaries[&session];
          let plans = plans
            .iter()
            .filter_map(|plan| Some(plan.id).filter(|_| plan.session == session))
            .collect::<Vec<_>>();
          PlanIds::set(&mut txn, &tributary.spec.genesis(), *block, &plans);

          let tx = Transaction::SubstrateBlock(*block);
          log::trace!(
            "processor message effected transaction {} {:?}",
            hex::encode(tx.hash()),
            &tx
          );
          log::trace!("providing transaction {}", hex::encode(tx.hash()));
          let res = tributary.tributary.provide_transaction(tx).await;
          if !(res.is_ok() || (res == Err(ProvidedError::AlreadyProvided))) {
            if res == Err(ProvidedError::LocalMismatchesOnChain) {
              // Spin, since this is a crit for this Tributary
              loop {
                log::error!(
                  "{}. tributary: {}, provided: SubstrateBlock({})",
                  "tributary added distinct provided to delayed locally provided TX",
                  hex::encode(tributary.spec.genesis()),
                  block,
                );
                sleep(Duration::from_secs(60)).await;
              }
            }
            panic!("provided an invalid transaction: {res:?}");
          }
        }

        None
      }
      // We'll only fire these if we are the Substrate signer, making the Tributary relevant
      coordinator::ProcessorMessage::InvalidParticipant { id, .. } |
      coordinator::ProcessorMessage::CosignPreprocess { id, .. } |
      coordinator::ProcessorMessage::BatchPreprocess { id, .. } |
      coordinator::ProcessorMessage::SubstrateShare { id, .. } => Some(id.session),
      coordinator::ProcessorMessage::CosignedBlock { block_number, block, signature } => {
        let cosigned_block = CosignedBlock {
          network,
          block_number: *block_number,
          block: *block,
          signature: {
            let mut arr = [0; 64];
            arr.copy_from_slice(signature);
            arr
          },
        };
        cosign_channel.send(cosigned_block).unwrap();
        let mut buf = vec![];
        cosigned_block.serialize(&mut buf).unwrap();
        P2p::broadcast(p2p, P2pMessageKind::CosignedBlock, buf).await;
        None
      }
    },
    // These don't return a relevant Tributary as there's no Tributary with action expected
    ProcessorMessage::Substrate(inner_msg) => match inner_msg {
      processor_messages::substrate::ProcessorMessage::Batch { batch } => {
        assert_eq!(
          batch.network, msg.network,
          "processor sent us a batch for a different network than it was for",
        );
        ExpectedBatchDb::save_expected_batch(&mut txn, batch);
        None
      }
      // If this is a new Batch, immediately publish it (if we can)
      processor_messages::substrate::ProcessorMessage::SignedBatch { batch } => {
        assert_eq!(
          batch.batch.network, msg.network,
          "processor sent us a signed batch for a different network than it was for",
        );

        log::debug!("received batch {:?} {}", batch.batch.network, batch.batch.id);

        // Save this batch to the disk
        BatchDb::set(&mut txn, batch.batch.network, batch.batch.id, &batch.clone());

        // Get the next-to-execute batch ID
        let Ok(mut next) = substrate::expected_next_batch(serai, network).await else {
          return false;
        };

        // Since we have a new batch, publish all batches yet to be published to Serai
        // This handles the edge-case where batch n+1 is signed before batch n is
        let mut batches = VecDeque::new();
        while let Some(batch) = BatchDb::get(&txn, network, next) {
          batches.push_back(batch);
          next += 1;
        }

        while let Some(batch) = batches.pop_front() {
          // If this Batch should no longer be published, continue
          let Ok(expected_next_batch) = substrate::expected_next_batch(serai, network).await else {
            return false;
          };
          if expected_next_batch > batch.batch.id {
            continue;
          }

          let tx = SeraiInInstructions::execute_batch(batch.clone());
          log::debug!("attempting to publish batch {:?} {}", batch.batch.network, batch.batch.id,);
          // This publish may fail if this transactions already exists in the mempool, which is
          // possible, or if this batch was already executed on-chain
          // Either case will have eventual resolution and be handled by the above check on if
          // this batch should execute
          let res = serai.publish(&tx).await;
          if res.is_ok() {
            log::info!(
              "published batch {network:?} {} (block {})",
              batch.batch.id,
              hex::encode(batch.batch.block),
            );
          } else {
            log::debug!(
              "couldn't publish batch {:?} {}: {:?}",
              batch.batch.network,
              batch.batch.id,
              res,
            );
            // If we failed to publish it, restore it
            batches.push_front(batch);
            // Sleep for a few seconds before retrying to prevent hammering the node
            sleep(Duration::from_secs(5)).await;
          }
        }

        None
      }
    },
  };

  // If we have a relevant Tributary, check it's actually still relevant and has yet to be retired
  if let Some(relevant_tributary_value) = relevant_tributary {
    if RetiredTributaryDb::get(
      &txn,
      ValidatorSet { network: msg.network, session: relevant_tributary_value },
    )
    .is_some()
    {
      relevant_tributary = None;
    }
  }

  // If there's a relevant Tributary...
  if let Some(relevant_tributary) = relevant_tributary {
    // Make sure we have it
    // Per the reasoning above, we only return a Tributary as relevant if we're a participant
    // Accordingly, we do *need* to have this Tributary now to handle it UNLESS the Tributary has
    // already completed and this is simply an old message (which we prior checked)
    let Some(ActiveTributary { spec, tributary }) = tributaries.get(&relevant_tributary) else {
      // Since we don't, sleep for a fraction of a second and return false, signaling we didn't
      // handle this message
      // At the start of the loop which calls this function, we'll check for new tributaries,
      // making this eventually resolve
      sleep(Duration::from_millis(100)).await;
      return false;
    };

    let genesis = spec.genesis();
    let pub_key = Ristretto::generator() * key.deref();

    let txs = match msg.msg.clone() {
      ProcessorMessage::KeyGen(inner_msg) => match inner_msg {
        key_gen::ProcessorMessage::Commitments { id, commitments } => {
          vec![Transaction::DkgCommitments {
            attempt: id.attempt,
            commitments,
            signed: Transaction::empty_signed(),
          }]
        }
        key_gen::ProcessorMessage::InvalidCommitments { id, faulty } => {
          // This doesn't have guaranteed timing
          //
          // While the party *should* be fatally slashed and not included in future attempts,
          // they'll actually be fatally slashed (assuming liveness before the Tributary retires)
          // and not included in future attempts *which begin after the latency window completes*
          let participant = spec
            .reverse_lookup_i(
              &crate::tributary::removed_as_of_dkg_attempt(&txn, spec.genesis(), id.attempt)
                .expect("participating in DKG attempt yet we didn't save who was removed"),
              faulty,
            )
            .unwrap();
          vec![Transaction::RemoveParticipantDueToDkg {
            participant,
            signed: Transaction::empty_signed(),
          }]
        }
        key_gen::ProcessorMessage::Shares { id, mut shares } => {
          // Create a MuSig-based machine to inform Substrate of this key generation
          let nonces = crate::tributary::dkg_confirmation_nonces(key, spec, &mut txn, id.attempt);

          let removed = crate::tributary::removed_as_of_dkg_attempt(&txn, genesis, id.attempt)
            .expect("participating in a DKG attempt yet we didn't track who was removed yet?");
          let our_i = spec
            .i(&removed, pub_key)
            .expect("processor message to DKG for an attempt we aren't a validator in");

          // `tx_shares` needs to be done here as while it can be serialized from the HashMap
          // without further context, it can't be deserialized without context
          let mut tx_shares = Vec::with_capacity(shares.len());
          for shares in &mut shares {
            tx_shares.push(vec![]);
            for i in 1 ..= spec.n(&removed) {
              let i = Participant::new(i).unwrap();
              if our_i.contains(&i) {
                if shares.contains_key(&i) {
                  panic!("processor sent us our own shares");
                }
                continue;
              }
              tx_shares.last_mut().unwrap().push(
                shares.remove(&i).expect("processor didn't send share for another validator"),
              );
            }
          }

          vec![Transaction::DkgShares {
            attempt: id.attempt,
            shares: tx_shares,
            confirmation_nonces: nonces,
            signed: Transaction::empty_signed(),
          }]
        }
        key_gen::ProcessorMessage::InvalidShare { id, accuser, faulty, blame } => {
          vec![Transaction::InvalidDkgShare {
            attempt: id.attempt,
            accuser,
            faulty,
            blame,
            signed: Transaction::empty_signed(),
          }]
        }
        key_gen::ProcessorMessage::GeneratedKeyPair { id, substrate_key, network_key } => {
          // TODO2: Check the KeyGenId fields

          // Tell the Tributary the key pair, get back the share for the MuSig signature
          let share = crate::tributary::generated_key_pair::<D>(
            &mut txn,
            key,
            spec,
            &KeyPair(Public(substrate_key), network_key.try_into().unwrap()),
            id.attempt,
          );

          // TODO: Move this into generated_key_pair?
          match share {
            Ok(share) => {
              vec![Transaction::DkgConfirmed {
                attempt: id.attempt,
                confirmation_share: share,
                signed: Transaction::empty_signed(),
              }]
            }
            Err(p) => {
              let participant = spec
                .reverse_lookup_i(
                  &crate::tributary::removed_as_of_dkg_attempt(&txn, spec.genesis(), id.attempt)
                    .expect("participating in DKG attempt yet we didn't save who was removed"),
                  p,
                )
                .unwrap();
              vec![Transaction::RemoveParticipantDueToDkg {
                participant,
                signed: Transaction::empty_signed(),
              }]
            }
          }
        }
        key_gen::ProcessorMessage::Blame { id, participant } => {
          let participant = spec
            .reverse_lookup_i(
              &crate::tributary::removed_as_of_dkg_attempt(&txn, spec.genesis(), id.attempt)
                .expect("participating in DKG attempt yet we didn't save who was removed"),
              participant,
            )
            .unwrap();
          vec![Transaction::RemoveParticipantDueToDkg {
            participant,
            signed: Transaction::empty_signed(),
          }]
        }
      },
      ProcessorMessage::Sign(msg) => match msg {
        sign::ProcessorMessage::InvalidParticipant { .. } => {
          // TODO: Locally increase slash points to maximum (distinct from an explicitly fatal
          // slash) and censor transactions (yet don't explicitly ban)
          vec![]
        }
        sign::ProcessorMessage::Preprocess { id, preprocesses } => {
          if id.attempt == 0 {
            FirstPreprocessDb::save_first_preprocess(
              &mut txn,
              network,
              RecognizedIdType::Plan,
              &id.id,
              &preprocesses,
            );

            vec![]
          } else {
            vec![Transaction::Sign(SignData {
              plan: id.id,
              attempt: id.attempt,
              label: Label::Preprocess,
              data: preprocesses,
              signed: Transaction::empty_signed(),
            })]
          }
        }
        sign::ProcessorMessage::Share { id, shares } => {
          vec![Transaction::Sign(SignData {
            plan: id.id,
            attempt: id.attempt,
            label: Label::Share,
            data: shares,
            signed: Transaction::empty_signed(),
          })]
        }
        sign::ProcessorMessage::Completed { session: _, id, tx } => {
          let r = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
          #[allow(non_snake_case)]
          let R = <Ristretto as Ciphersuite>::generator() * r.deref();
          let mut tx = Transaction::SignCompleted {
            plan: id,
            tx_hash: tx,
            first_signer: pub_key,
            signature: SchnorrSignature { R, s: <Ristretto as Ciphersuite>::F::ZERO },
          };
          let signed = SchnorrSignature::sign(key, r, tx.sign_completed_challenge());
          match &mut tx {
            Transaction::SignCompleted { signature, .. } => {
              *signature = signed;
            }
            _ => unreachable!(),
          }
          vec![tx]
        }
      },
      ProcessorMessage::Coordinator(inner_msg) => match inner_msg {
        coordinator::ProcessorMessage::SubstrateBlockAck { .. } => unreachable!(),
        coordinator::ProcessorMessage::InvalidParticipant { .. } => {
          // TODO: Locally increase slash points to maximum (distinct from an explicitly fatal
          // slash) and censor transactions (yet don't explicitly ban)
          vec![]
        }
        coordinator::ProcessorMessage::CosignPreprocess { id, preprocesses } => {
          vec![Transaction::SubstrateSign(SignData {
            plan: id.id,
            attempt: id.attempt,
            label: Label::Preprocess,
            data: preprocesses.into_iter().map(Into::into).collect(),
            signed: Transaction::empty_signed(),
          })]
        }
        coordinator::ProcessorMessage::BatchPreprocess { id, block, preprocesses } => {
          log::info!(
            "informed of batch (sign ID {}, attempt {}) for block {}",
            hex::encode(id.id.encode()),
            id.attempt,
            hex::encode(block),
          );

          // If this is the first attempt instance, wait until we synchronize around the batch
          // first
          if id.attempt == 0 {
            FirstPreprocessDb::save_first_preprocess(
              &mut txn,
              spec.set().network,
              RecognizedIdType::Batch,
              &{
                let SubstrateSignableId::Batch(id) = id.id else {
                  panic!("BatchPreprocess SubstrateSignableId wasn't Batch")
                };
                id.to_le_bytes()
              },
              &preprocesses.into_iter().map(Into::into).collect::<Vec<_>>(),
            );

            let intended = Transaction::Batch {
              block: block.0,
              batch: match id.id {
                SubstrateSignableId::Batch(id) => id,
                _ => panic!("BatchPreprocess did not contain Batch ID"),
              },
            };

            // If this is the new key's first Batch, only create this TX once we verify all
            // all prior published `Batch`s
            // TODO: This assumes BatchPreprocess is immediately after Batch
            // Ensure that assumption
            let last_received = LastReceivedBatchDb::get(&txn, msg.network).unwrap();
            let handover_batch = HandoverBatchDb::get(&txn, spec.set());
            let mut queue = false;
            if let Some(handover_batch) = handover_batch {
              // There is a race condition here. We may verify all `Batch`s from the prior set,
              // start signing the handover `Batch` `n`, start signing `n+1`, have `n+1` signed
              // before `n` (or at the same time), yet then the prior set forges a malicious
              // `Batch` `n`.
              //
              // The malicious `Batch` `n` would be publishable to Serai, as Serai can't
              // distinguish what's intended to be a handover `Batch`, yet then anyone could
              // publish the new set's `n+1`, causing their acceptance of the handover.
              //
              // To fix this, if this is after the handover `Batch` and we have yet to verify
              // publication of the handover `Batch`, don't yet yield the provided.
              if last_received > handover_batch {
                if let Some(last_verified) = LastVerifiedBatchDb::get(&txn, msg.network) {
                  if last_verified < handover_batch {
                    queue = true;
                  }
                } else {
                  queue = true;
                }
              }
            } else {
              HandoverBatchDb::set_handover_batch(&mut txn, spec.set(), last_received);
              // If this isn't the first batch, meaning we do have to verify all prior batches, and
              // the prior Batch hasn't been verified yet...
              if (last_received != 0) &&
                LastVerifiedBatchDb::get(&txn, msg.network)
                  .map_or(true, |last_verified| last_verified < (last_received - 1))
              {
                // Withhold this TX until we verify all prior `Batch`s
                queue = true;
              }
            }

            if queue {
              QueuedBatchesDb::queue(&mut txn, spec.set(), &intended);
              vec![]
            } else {
              // Because this is post-verification of the handover batch, take all queued `Batch`s
              // now to ensure we don't provide this before an already queued Batch
              // This *may* be an unreachable case due to how last_verified_batch is set, yet it
              // doesn't hurt to have as a defensive pattern
              let mut res = QueuedBatchesDb::take(&mut txn, spec.set());
              res.push(intended);
              res
            }
          } else {
            vec![Transaction::SubstrateSign(SignData {
              plan: id.id,
              attempt: id.attempt,
              label: Label::Preprocess,
              data: preprocesses.into_iter().map(Into::into).collect(),
              signed: Transaction::empty_signed(),
            })]
          }
        }
        coordinator::ProcessorMessage::SubstrateShare { id, shares } => {
          vec![Transaction::SubstrateSign(SignData {
            plan: id.id,
            attempt: id.attempt,
            label: Label::Share,
            data: shares.into_iter().map(|share| share.to_vec()).collect(),
            signed: Transaction::empty_signed(),
          })]
        }
        #[allow(clippy::match_same_arms)] // Allowed to preserve layout
        coordinator::ProcessorMessage::CosignedBlock { .. } => unreachable!(),
      },
      ProcessorMessage::Substrate(inner_msg) => match inner_msg {
        processor_messages::substrate::ProcessorMessage::Batch { .. } |
        processor_messages::substrate::ProcessorMessage::SignedBatch { .. } => unreachable!(),
      },
    };

    // If this created transactions, publish them
    for mut tx in txs {
      log::trace!("processor message effected transaction {} {:?}", hex::encode(tx.hash()), &tx);

      match tx.kind() {
        TransactionKind::Provided(_) => {
          log::trace!("providing transaction {}", hex::encode(tx.hash()));
          let res = tributary.provide_transaction(tx.clone()).await;
          if !(res.is_ok() || (res == Err(ProvidedError::AlreadyProvided))) {
            if res == Err(ProvidedError::LocalMismatchesOnChain) {
              // Spin, since this is a crit for this Tributary
              loop {
                log::error!(
                  "{}. tributary: {}, provided: {:?}",
                  "tributary added distinct provided to delayed locally provided TX",
                  hex::encode(spec.genesis()),
                  &tx,
                );
                sleep(Duration::from_secs(60)).await;
              }
            }
            panic!("provided an invalid transaction: {res:?}");
          }
        }
        TransactionKind::Unsigned => {
          log::trace!("publishing unsigned transaction {}", hex::encode(tx.hash()));
          match tributary.add_transaction(tx.clone()).await {
            Ok(_) => {}
            Err(e) => panic!("created an invalid unsigned transaction: {e:?}"),
          }
        }
        TransactionKind::Signed(_, _) => {
          tx.sign(&mut OsRng, genesis, key);
          tributary::publish_signed_transaction(&mut txn, tributary, tx).await;
        }
      }
    }
  }

  HandledMessageDb::set(&mut txn, msg.network, &msg.id);
  txn.commit();

  true
}

#[allow(clippy::too_many_arguments)]
async fn handle_processor_messages<D: Db, Pro: Processors, P: P2p>(
  mut db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: Arc<Serai>,
  processors: Pro,
  p2p: P,
  cosign_channel: mpsc::UnboundedSender<CosignedBlock>,
  network: NetworkId,
  mut tributary_event: mpsc::UnboundedReceiver<TributaryEvent<D, P>>,
) {
  let mut tributaries = HashMap::new();
  loop {
    match tributary_event.try_recv() {
      Ok(event) => match event {
        TributaryEvent::NewTributary(tributary) => {
          let set = tributary.spec.set();
          assert_eq!(set.network, network);
          tributaries.insert(set.session, tributary);
        }
        TributaryEvent::TributaryRetired(set) => {
          tributaries.remove(&set.session);
        }
      },
      Err(mpsc::error::TryRecvError::Empty) => {}
      Err(mpsc::error::TryRecvError::Disconnected) => {
        panic!("handle_processor_messages tributary_event sender closed")
      }
    }

    // TODO: Check this ID is sane (last handled ID or expected next ID)
    let Ok(msg) = tokio::time::timeout(Duration::from_secs(1), processors.recv(network)).await
    else {
      continue;
    };
    log::trace!("entering handle_processor_message for {:?}", network);
    if handle_processor_message(
      &mut db,
      &key,
      &serai,
      &p2p,
      &cosign_channel,
      &tributaries,
      network,
      &msg,
    )
    .await
    {
      processors.ack(msg).await;
    }
    log::trace!("exited handle_processor_message for {:?}", network);
  }
}

#[allow(clippy::too_many_arguments)]
async fn handle_cosigns_and_batch_publication<D: Db, P: P2p>(
  mut db: D,
  network: NetworkId,
  mut tributary_event: mpsc::UnboundedReceiver<TributaryEvent<D, P>>,
) {
  let mut tributaries = HashMap::new();
  'outer: loop {
    // TODO: Create a better async flow for this, as this does still hammer this task
    tokio::task::yield_now().await;

    match tributary_event.try_recv() {
      Ok(event) => match event {
        TributaryEvent::NewTributary(tributary) => {
          let set = tributary.spec.set();
          assert_eq!(set.network, network);
          tributaries.insert(set.session, tributary);
        }
        TributaryEvent::TributaryRetired(set) => {
          tributaries.remove(&set.session);
        }
      },
      Err(mpsc::error::TryRecvError::Empty) => {}
      Err(mpsc::error::TryRecvError::Disconnected) => {
        panic!("handle_processor_messages tributary_event sender closed")
      }
    }

    // Handle pending cosigns
    {
      let mut txn = db.txn();
      while let Some((session, block, hash)) = CosignTransactions::try_recv(&mut txn, network) {
        let Some(ActiveTributary { spec, tributary }) = tributaries.get(&session) else {
          log::warn!("didn't yet have tributary we're supposed to cosign with");
          break;
        };
        log::info!(
          "{network:?} {session:?} cosigning block #{block} (hash {}...)",
          hex::encode(&hash[.. 8])
        );
        let tx = Transaction::CosignSubstrateBlock(hash);
        let res = tributary.provide_transaction(tx.clone()).await;
        if !(res.is_ok() || (res == Err(ProvidedError::AlreadyProvided))) {
          if res == Err(ProvidedError::LocalMismatchesOnChain) {
            // Spin, since this is a crit for this Tributary
            loop {
              log::error!(
                "{}. tributary: {}, provided: {:?}",
                "tributary added distinct CosignSubstrateBlock",
                hex::encode(spec.genesis()),
                &tx,
              );
              sleep(Duration::from_secs(60)).await;
            }
          }
          panic!("provided an invalid CosignSubstrateBlock: {res:?}");
        }
      }
      txn.commit();
    }

    // Verify any publifshed `Batch`s
    {
      let _hvq_lock = HANDOVER_VERIFY_QUEUE_LOCK.get_or_init(|| Mutex::new(())).lock().await;
      let mut txn = db.txn();
      let mut to_publish = vec![];
      let start_id =
        LastVerifiedBatchDb::get(&txn, network).map_or(0, |already_verified| already_verified + 1);
      if let Some(last_id) =
        substrate::verify_published_batches::<D>(&mut txn, network, u32::MAX).await
      {
        // Check if any of these `Batch`s were a handover `Batch` or the `Batch` before a handover
        // `Batch`
        // If so, we need to publish queued provided `Batch` transactions
        for batch in start_id ..= last_id {
          let is_pre_handover = LookupHandoverBatchDb::get(&txn, network, batch + 1);
          if let Some(session) = is_pre_handover {
            let set = ValidatorSet { network, session };
            let mut queued = QueuedBatchesDb::take(&mut txn, set);
            // is_handover_batch is only set for handover `Batch`s we're participating in, making
            // this safe
            if queued.is_empty() {
              panic!("knew the next Batch was a handover yet didn't queue it");
            }

            // Only publish the handover Batch
            to_publish.push((set.session, queued.remove(0)));
            // Re-queue the remaining batches
            for remaining in queued {
              QueuedBatchesDb::queue(&mut txn, set, &remaining);
            }
          }

          let is_handover = LookupHandoverBatchDb::get(&txn, network, batch);
          if let Some(session) = is_handover {
            for queued in QueuedBatchesDb::take(&mut txn, ValidatorSet { network, session }) {
              to_publish.push((session, queued));
            }
          }
        }
      }

      for (session, tx) in to_publish {
        let Some(ActiveTributary { spec, tributary }) = tributaries.get(&session) else {
          log::warn!("didn't yet have tributary we're supposed to provide a queued Batch for");
          // Safe since this will drop the txn updating the most recently queued batch
          continue 'outer;
        };
        log::debug!("providing Batch transaction {:?}", &tx);
        let res = tributary.provide_transaction(tx.clone()).await;
        if !(res.is_ok() || (res == Err(ProvidedError::AlreadyProvided))) {
          if res == Err(ProvidedError::LocalMismatchesOnChain) {
            // Spin, since this is a crit for this Tributary
            loop {
              log::error!(
                "{}. tributary: {}, provided: {:?}",
                "tributary added distinct Batch",
                hex::encode(spec.genesis()),
                &tx,
              );
              sleep(Duration::from_secs(60)).await;
            }
          }
          panic!("provided an invalid Batch: {res:?}");
        }
      }

      txn.commit();
    }
  }
}

pub async fn handle_processors<D: Db, Pro: Processors, P: P2p>(
  db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: Arc<Serai>,
  processors: Pro,
  p2p: P,
  cosign_channel: mpsc::UnboundedSender<CosignedBlock>,
  mut tributary_event: broadcast::Receiver<TributaryEvent<D, P>>,
) {
  let mut channels = HashMap::new();
  for network in serai_client::primitives::NETWORKS {
    if network == NetworkId::Serai {
      continue;
    }
    let (processor_send, processor_recv) = mpsc::unbounded_channel();
    tokio::spawn(handle_processor_messages(
      db.clone(),
      key.clone(),
      serai.clone(),
      processors.clone(),
      p2p.clone(),
      cosign_channel.clone(),
      network,
      processor_recv,
    ));
    let (cosign_send, cosign_recv) = mpsc::unbounded_channel();
    tokio::spawn(handle_cosigns_and_batch_publication(db.clone(), network, cosign_recv));
    channels.insert(network, (processor_send, cosign_send));
  }

  // Listen to new tributary events
  loop {
    match tributary_event.recv().await.unwrap() {
      TributaryEvent::NewTributary(tributary) => {
        let (c1, c2) = &channels[&tributary.spec.set().network];
        c1.send(TributaryEvent::NewTributary(tributary.clone())).unwrap();
        c2.send(TributaryEvent::NewTributary(tributary)).unwrap();
      }
      TributaryEvent::TributaryRetired(set) => {
        let (c1, c2) = &channels[&set.network];
        c1.send(TributaryEvent::TributaryRetired(set)).unwrap();
        c2.send(TributaryEvent::TributaryRetired(set)).unwrap();
      }
    };
  }
}

pub async fn run<D: Db, Pro: Processors, P: P2p>(
  raw_db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  p2p: P,
  processors: Pro,
  serai: Arc<Serai>,
) {
  let (new_tributary_spec_send, mut new_tributary_spec_recv) = mpsc::unbounded_channel();
  // Reload active tributaries from the database
  for spec in ActiveTributaryDb::active_tributaries(&raw_db).1 {
    new_tributary_spec_send.send(spec).unwrap();
  }

  let (tributary_retired_send, mut tributary_retired_recv) = mpsc::unbounded_channel();

  // Handle new Substrate blocks
  tokio::spawn(crate::substrate::scan_task(
    raw_db.clone(),
    key.clone(),
    processors.clone(),
    serai.clone(),
    new_tributary_spec_send,
    tributary_retired_send,
  ));

  // Handle the Tributaries

  // This should be large enough for an entire rotation of all tributaries
  // If it's too small, the coordinator fail to boot, which is a decent sanity check
  let (tributary_event, mut tributary_event_listener_1) = broadcast::channel(32);
  let tributary_event_listener_2 = tributary_event.subscribe();
  let tributary_event_listener_3 = tributary_event.subscribe();
  let tributary_event_listener_4 = tributary_event.subscribe();
  let tributary_event_listener_5 = tributary_event.subscribe();

  // Emit TributaryEvent::TributaryRetired
  tokio::spawn({
    let tributary_event = tributary_event.clone();
    async move {
      loop {
        let retired = tributary_retired_recv.recv().await.unwrap();
        tributary_event.send(TributaryEvent::TributaryRetired(retired)).map_err(|_| ()).unwrap();
      }
    }
  });

  // Spawn a task to further add Tributaries as needed
  tokio::spawn({
    let raw_db = raw_db.clone();
    let key = key.clone();
    let processors = processors.clone();
    let p2p = p2p.clone();
    async move {
      loop {
        let spec = new_tributary_spec_recv.recv().await.unwrap();
        // Uses an inner task as Tributary::new may take several seconds
        tokio::spawn({
          let raw_db = raw_db.clone();
          let key = key.clone();
          let processors = processors.clone();
          let p2p = p2p.clone();
          let tributary_event = tributary_event.clone();
          async move {
            add_tributary(raw_db, key, &processors, p2p, &tributary_event, spec).await;
          }
        });
      }
    }
  });

  // When we reach synchrony on an event requiring signing, send our preprocess for it
  // TODO: Properly place this into the Tributary scanner, as it's a mess out here
  let recognized_id = {
    let raw_db = raw_db.clone();
    let key = key.clone();

    let tributaries = Arc::new(RwLock::new(HashMap::new()));
    // Spawn a task to maintain a local view of the tributaries for whenever recognized_id is
    // called
    tokio::spawn({
      let tributaries = tributaries.clone();
      let mut set_to_genesis = HashMap::new();
      async move {
        loop {
          match tributary_event_listener_1.recv().await {
            Ok(TributaryEvent::NewTributary(tributary)) => {
              set_to_genesis.insert(tributary.spec.set(), tributary.spec.genesis());
              tributaries.write().await.insert(tributary.spec.genesis(), tributary.tributary);
            }
            Ok(TributaryEvent::TributaryRetired(set)) => {
              if let Some(genesis) = set_to_genesis.remove(&set) {
                tributaries.write().await.remove(&genesis);
              }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {
              panic!("recognized_id lagged to handle tributary_event")
            }
            Err(broadcast::error::RecvError::Closed) => panic!("tributary_event sender closed"),
          }
        }
      }
    });

    move |set: ValidatorSet, genesis, id_type, id: Vec<u8>| {
      log::debug!("recognized ID {:?} {}", id_type, hex::encode(&id));
      let mut raw_db = raw_db.clone();
      let key = key.clone();
      let tributaries = tributaries.clone();
      async move {
        // The transactions for these are fired before the preprocesses are actually
        // received/saved, creating a race between Tributary ack and the availability of all
        // Preprocesses
        // This waits until the necessary preprocess is available 0,
        let get_preprocess = |raw_db, id_type, id| async move {
          loop {
            let Some(preprocess) = FirstPreprocessDb::get(raw_db, set.network, id_type, id) else {
              log::warn!("waiting for preprocess for recognized ID");
              sleep(Duration::from_millis(100)).await;
              continue;
            };
            return preprocess;
          }
        };

        let mut tx = match id_type {
          RecognizedIdType::Batch => Transaction::SubstrateSign(SignData {
            data: get_preprocess(&raw_db, id_type, &id).await,
            plan: SubstrateSignableId::Batch(u32::from_le_bytes(id.try_into().unwrap())),
            label: Label::Preprocess,
            attempt: 0,
            signed: Transaction::empty_signed(),
          }),

          RecognizedIdType::Plan => Transaction::Sign(SignData {
            data: get_preprocess(&raw_db, id_type, &id).await,
            plan: id.try_into().unwrap(),
            label: Label::Preprocess,
            attempt: 0,
            signed: Transaction::empty_signed(),
          }),
        };

        tx.sign(&mut OsRng, genesis, &key);

        let mut first = true;
        loop {
          if !first {
            sleep(Duration::from_millis(100)).await;
          }
          first = false;

          let tributaries = tributaries.read().await;
          let Some(tributary) = tributaries.get(&genesis) else {
            // If we don't have this Tributary because it's retired, break and move on
            if RetiredTributaryDb::get(&raw_db, set).is_some() {
              break;
            }

            // This may happen if the task above is simply slow
            log::warn!("tributary we don't have yet came to consensus on an Batch");
            continue;
          };
          // This is safe to perform multiple times and solely needs atomicity with regards to
          // itself
          // TODO: Should this not take a txn accordingly? It's best practice to take a txn, yet
          // taking a txn fails to declare its achieved independence
          let mut txn = raw_db.txn();
          tributary::publish_signed_transaction(&mut txn, tributary, tx).await;
          txn.commit();
          break;
        }
      }
    }
  };

  // Handle new blocks for each Tributary
  {
    let raw_db = raw_db.clone();
    tokio::spawn(tributary::scanner::scan_tributaries_task(
      raw_db,
      key.clone(),
      recognized_id,
      processors.clone(),
      serai.clone(),
      tributary_event_listener_2,
    ));
  }

  // Spawn the heartbeat task, which will trigger syncing if there hasn't been a Tributary block
  // in a while (presumably because we're behind)
  tokio::spawn(p2p::heartbeat_tributaries_task(p2p.clone(), tributary_event_listener_3));

  // Create the Cosign evaluator
  let cosign_channel = CosignEvaluator::new(raw_db.clone(), p2p.clone(), serai.clone());

  // Handle P2P messages
  tokio::spawn(p2p::handle_p2p_task(
    p2p.clone(),
    cosign_channel.clone(),
    tributary_event_listener_4,
  ));

  // Handle all messages from processors
  handle_processors(
    raw_db,
    key,
    serai,
    processors,
    p2p,
    cosign_channel,
    tributary_event_listener_5,
  )
  .await;
}

#[tokio::main]
async fn main() {
  // Override the panic handler with one which will panic if any tokio task panics
  {
    let existing = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
      existing(panic);
      const MSG: &str = "exiting the process due to a task panicking";
      println!("{MSG}");
      log::error!("{MSG}");
      std::process::exit(1);
    }));
  }

  if std::env::var("RUST_LOG").is_err() {
    std::env::set_var("RUST_LOG", serai_env::var("RUST_LOG").unwrap_or_else(|| "info".to_string()));
  }
  env_logger::init();

  log::info!("starting coordinator service...");

  #[allow(unused_variables, unreachable_code)]
  let db = {
    #[cfg(all(feature = "parity-db", feature = "rocksdb"))]
    panic!("built with parity-db and rocksdb");
    #[cfg(all(feature = "parity-db", not(feature = "rocksdb")))]
    let db =
      serai_db::new_parity_db(&serai_env::var("DB_PATH").expect("path to DB wasn't specified"));
    #[cfg(feature = "rocksdb")]
    let db =
      serai_db::new_rocksdb(&serai_env::var("DB_PATH").expect("path to DB wasn't specified"));
    db
  };

  let key = {
    let mut key_hex = serai_env::var("SERAI_KEY").expect("Serai key wasn't provided");
    let mut key_vec = hex::decode(&key_hex).map_err(|_| ()).expect("Serai key wasn't hex-encoded");
    key_hex.zeroize();
    if key_vec.len() != 32 {
      key_vec.zeroize();
      panic!("Serai key had an invalid length");
    }
    let mut key_bytes = [0; 32];
    key_bytes.copy_from_slice(&key_vec);
    key_vec.zeroize();
    let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::from_repr(key_bytes).unwrap());
    key_bytes.zeroize();
    key
  };

  let processors = Arc::new(MessageQueue::from_env(Service::Coordinator));

  let serai = (async {
    loop {
      let Ok(serai) = Serai::new(format!(
        "http://{}:9944",
        serai_env::var("SERAI_HOSTNAME").expect("Serai hostname wasn't provided")
      ))
      .await
      else {
        log::error!("couldn't connect to the Serai node");
        sleep(Duration::from_secs(5)).await;
        continue;
      };
      log::info!("made initial connection to Serai node");
      return Arc::new(serai);
    }
  })
  .await;
  let p2p = LibP2p::new(serai.clone());
  run(db, key, p2p, processors, serai).await
}
