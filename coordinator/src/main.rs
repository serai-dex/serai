use core::ops::Deref;
use std::{
  sync::Arc,
  time::Duration,
  collections::{VecDeque, HashMap},
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
use serai_env as env;

use serai_client::{
  primitives::NetworkId,
  validator_sets::primitives::{Session, ValidatorSet},
  Public, Serai, SeraiInInstructions,
};

use message_queue::{Service, client::MessageQueue};

use tokio::{
  sync::{RwLock, mpsc, broadcast},
  time::sleep,
};

use ::tributary::{ProvidedError, TransactionKind, TransactionTrait, Block, Tributary};

mod tributary;
use crate::tributary::{
  TributarySpec, SignData, Transaction, TributaryDb, NonceDecider, scanner::RecognizedIdType,
};

mod db;
use db::MainDb;

mod p2p;
pub use p2p::*;

use processor_messages::{key_gen, sign, coordinator, ProcessorMessage};

pub mod processors;
use processors::Processors;

mod substrate;
use substrate::{SubstrateDb, is_active_set};

#[cfg(test)]
pub mod tests;

#[derive(Clone)]
pub struct ActiveTributary<D: Db, P: P2p> {
  pub spec: TributarySpec,
  pub tributary: Arc<Tributary<D, Transaction, P>>,
}

// Creates a new tributary and sends it to all listeners.
// TODO: retire_tributary
async fn add_tributary<D: Db, Pro: Processors, P: P2p>(
  db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  processors: &Pro,
  p2p: P,
  tributaries: &broadcast::Sender<ActiveTributary<D, P>>,
  spec: TributarySpec,
) {
  log::info!("adding tributary {:?}", spec.set());

  let tributary = Tributary::<_, Transaction, _>::new(
    // TODO2: Use a db on a distinct volume to protect against DoS attacks
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
  processors
    .send(
      set.network,
      processor_messages::key_gen::CoordinatorMessage::GenerateKey {
        id: processor_messages::key_gen::KeyGenId { set, attempt: 0 },
        params: frost::ThresholdParams::new(
          spec.t(),
          spec.n(),
          spec
            .i(Ristretto::generator() * key.deref())
            .expect("adding a tributary for a set we aren't in set for"),
        )
        .unwrap(),
      },
    )
    .await;

  tributaries
    .send(ActiveTributary { spec, tributary: Arc::new(tributary) })
    .map_err(|_| "all ActiveTributary recipients closed")
    .unwrap();
}

async fn publish_signed_transaction<D: Db, P: P2p>(
  txn: &mut D::Transaction<'_>,
  tributary: &Tributary<D, Transaction, P>,
  tx: Transaction,
) {
  log::debug!("publishing transaction {}", hex::encode(tx.hash()));

  let signer = if let TransactionKind::Signed(signed) = tx.kind() {
    let signer = signed.signer;

    // Safe as we should deterministically create transactions, meaning if this is already on-disk,
    // it's what we're saving now
    MainDb::<D>::save_signed_transaction(txn, signed.nonce, tx);

    signer
  } else {
    panic!("non-signed transaction passed to publish_signed_transaction");
  };

  // If we're trying to publish 5, when the last transaction published was 3, this will delay
  // publication until the point in time we publish 4
  while let Some(tx) = MainDb::<D>::take_signed_transaction(
    txn,
    tributary
      .next_nonce(signer)
      .await
      .expect("we don't have a nonce, meaning we aren't a participant on this tributary"),
  ) {
    // TODO: Assert if we didn't create a valid transaction
    // We need to return a proper error here to enable that, due to a race condition around
    // multiple publications
    tributary.add_transaction(tx).await;
  }
}

async fn handle_processor_message<D: Db, P: P2p>(
  db: &mut D,
  key: &Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: &Serai,
  tributaries: &HashMap<Session, ActiveTributary<D, P>>,
  network: NetworkId,
  msg: &processors::Message,
) -> bool {
  if MainDb::<D>::handled_message(db, msg.network, msg.id) {
    return true;
  }

  let mut txn = db.txn();

  let mut relevant_tributary = match &msg.msg {
    // We'll only receive these if we fired GenerateKey, which we'll only do if if we're
    // in-set, making the Tributary relevant
    ProcessorMessage::KeyGen(inner_msg) => match inner_msg {
      key_gen::ProcessorMessage::Commitments { id, .. } => Some(id.set.session),
      key_gen::ProcessorMessage::Shares { id, .. } => Some(id.set.session),
      key_gen::ProcessorMessage::GeneratedKeyPair { id, .. } => Some(id.set.session),
    },
    // TODO: Review replacing key with Session in messages?
    ProcessorMessage::Sign(inner_msg) => match inner_msg {
      // We'll only receive Preprocess and Share if we're actively signing
      sign::ProcessorMessage::Preprocess { id, .. } => {
        Some(SubstrateDb::<D>::session_for_key(&txn, &id.key).unwrap())
      }
      sign::ProcessorMessage::Share { id, .. } => {
        Some(SubstrateDb::<D>::session_for_key(&txn, &id.key).unwrap())
      }
      // While the Processor's Scanner will always emit Completed, that's routed through the
      // Signer and only becomes a ProcessorMessage::Completed if the Signer is present and
      // confirms it
      sign::ProcessorMessage::Completed { key, .. } => {
        Some(SubstrateDb::<D>::session_for_key(&txn, key).unwrap())
      }
    },
    ProcessorMessage::Coordinator(inner_msg) => match inner_msg {
      // This is a special case as it's relevant to *all* Tributaries for this network
      // It doesn't return a Tributary to become `relevant_tributary` though
      coordinator::ProcessorMessage::SubstrateBlockAck { network, block, plans } => {
        assert_eq!(
          *network, msg.network,
          "processor claimed to be a different network than it was for SubstrateBlockAck",
        );

        // TODO: Find all Tributaries active at this Substrate block, and make sure we have
        // them all (if we were present in them)

        for tributary in tributaries.values() {
          // TODO: This needs to be scoped per multisig
          TributaryDb::<D>::set_plan_ids(&mut txn, tributary.spec.genesis(), *block, plans);

          let tx = Transaction::SubstrateBlock(*block);
          log::trace!("processor message effected transaction {}", hex::encode(tx.hash()));
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
      coordinator::ProcessorMessage::BatchPreprocess { id, .. } => {
        Some(SubstrateDb::<D>::session_for_key(&txn, &id.key).unwrap())
      }
      coordinator::ProcessorMessage::BatchShare { id, .. } => {
        Some(SubstrateDb::<D>::session_for_key(&txn, &id.key).unwrap())
      }
    },
    // These don't return a relevant Tributary as there's no Tributary with action expected
    ProcessorMessage::Substrate(inner_msg) => match inner_msg {
      processor_messages::substrate::ProcessorMessage::Batch { batch } => {
        assert_eq!(
          batch.network, msg.network,
          "processor sent us a batch for a different network than it was for",
        );
        let this_batch_id = batch.id;
        MainDb::<D>::save_expected_batch(&mut txn, batch);

        // Re-define batch
        // We can't drop it, yet it shouldn't be accidentally used in the following block
        #[allow(clippy::let_unit_value, unused_variables)]
        let batch = ();

        // This won't be complete, as this call is when a `Batch` message is received, which
        // will be before we get a `SignedBatch`
        // It is, however, incremental
        // When we need a complete version, we use another call, continuously called as-needed
        substrate::verify_published_batches::<D>(&mut txn, msg.network, this_batch_id).await;

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
        MainDb::<D>::save_batch(&mut txn, batch.clone());

        // Get the next-to-execute batch ID
        let mut next = substrate::get_expected_next_batch(serai, network).await;

        // Since we have a new batch, publish all batches yet to be published to Serai
        // This handles the edge-case where batch n+1 is signed before batch n is
        let mut batches = VecDeque::new();
        while let Some(batch) = MainDb::<D>::batch(&txn, network, next) {
          batches.push_back(batch);
          next += 1;
        }

        let start_id = batches.front().map(|batch| batch.batch.id);
        let last_id = batches.back().map(|batch| batch.batch.id);
        while let Some(batch) = batches.pop_front() {
          // If this Batch should no longer be published, continue
          if substrate::get_expected_next_batch(serai, network).await > batch.batch.id {
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
        // Verify the `Batch`s we just published
        if let Some(last_id) = last_id {
          loop {
            let verified =
              substrate::verify_published_batches::<D>(&mut txn, msg.network, last_id).await;
            if verified == Some(last_id) {
              break;
            }
          }
        }

        // Check if any of these `Batch`s were a handover `Batch`
        // If so, we need to publish any delayed `Batch` provided transactions
        let mut relevant = None;
        if let Some(start_id) = start_id {
          let last_id = last_id.unwrap();
          for batch in start_id .. last_id {
            if let Some(set) = MainDb::<D>::is_handover_batch(&txn, msg.network, batch) {
              // relevant may already be Some. This is a safe over-write, as we don't need to
              // be concerned for handovers of Tributaries which have completed their handovers
              // While this does bypass the checks that Tributary would've performed at the
              // time, if we ever actually participate in a handover, we will verify *all*
              // prior `Batch`s, including the ones which would've been explicitly verified
              // then
              //
              // We should only declare this session relevant if it's relevant to us
              // We only set handover `Batch`s when we're trying to produce said `Batch`, so this
              // would be a `Batch` we were involved in the production of
              // Accordingly, iy's relevant
              relevant = Some(set.session);
            }
          }
        }
        relevant
      }
    },
  };

  // If we have a relevant Tributary, check it's actually still relevant and has yet to be retired
  if let Some(relevant_tributary_value) = relevant_tributary {
    if !is_active_set(
      serai,
      ValidatorSet { network: msg.network, session: relevant_tributary_value },
    )
    .await
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
      // At the start of the loop which calls this function, we'll check for new tributaries, making
      // this eventually resolve
      sleep(Duration::from_millis(100)).await;
      return false;
    };

    let genesis = spec.genesis();
    let pub_key = Ristretto::generator() * key.deref();

    let txs = match msg.msg.clone() {
      ProcessorMessage::KeyGen(inner_msg) => match inner_msg {
        key_gen::ProcessorMessage::Commitments { id, commitments } => {
          vec![Transaction::DkgCommitments(id.attempt, commitments, Transaction::empty_signed())]
        }
        key_gen::ProcessorMessage::Shares { id, mut shares } => {
          // Create a MuSig-based machine to inform Substrate of this key generation
          let nonces = crate::tributary::dkg_confirmation_nonces(key, spec, id.attempt);

          let mut tx_shares = Vec::with_capacity(shares.len());
          for i in 1 ..= spec.n() {
            let i = Participant::new(i).unwrap();
            if i ==
              spec
                .i(pub_key)
                .expect("processor message to DKG for a session we aren't a validator in")
            {
              continue;
            }
            tx_shares
              .push(shares.remove(&i).expect("processor didn't send share for another validator"));
          }

          vec![Transaction::DkgShares {
            attempt: id.attempt,
            shares: tx_shares,
            confirmation_nonces: nonces,
            signed: Transaction::empty_signed(),
          }]
        }
        key_gen::ProcessorMessage::GeneratedKeyPair { id, substrate_key, network_key } => {
          assert_eq!(
            id.set.network, msg.network,
            "processor claimed to be a different network than it was for GeneratedKeyPair",
          );
          // TODO2: Also check the other KeyGenId fields

          // Tell the Tributary the key pair, get back the share for the MuSig signature
          let share = crate::tributary::generated_key_pair::<D>(
            &mut txn,
            key,
            spec,
            &(Public(substrate_key), network_key.try_into().unwrap()),
            id.attempt,
          );

          match share {
            Ok(share) => {
              vec![Transaction::DkgConfirmed(id.attempt, share, Transaction::empty_signed())]
            }
            Err(p) => {
              todo!("participant {p:?} sent invalid DKG confirmation preprocesses")
            }
          }
        }
      },
      ProcessorMessage::Sign(msg) => match msg {
        sign::ProcessorMessage::Preprocess { id, preprocess } => {
          if id.attempt == 0 {
            MainDb::<D>::save_first_preprocess(&mut txn, network, id.id, preprocess);

            vec![]
          } else {
            vec![Transaction::SignPreprocess(SignData {
              plan: id.id,
              attempt: id.attempt,
              data: preprocess,
              signed: Transaction::empty_signed(),
            })]
          }
        }
        sign::ProcessorMessage::Share { id, share } => vec![Transaction::SignShare(SignData {
          plan: id.id,
          attempt: id.attempt,
          data: share,
          signed: Transaction::empty_signed(),
        })],
        sign::ProcessorMessage::Completed { key: _, id, tx } => {
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
        coordinator::ProcessorMessage::BatchPreprocess { id, block, preprocess } => {
          log::info!(
            "informed of batch (sign ID {}, attempt {}) for block {}",
            hex::encode(id.id),
            id.attempt,
            hex::encode(block),
          );

          // If this is the first attempt instance, wait until we synchronize around the batch
          // first
          if id.attempt == 0 {
            MainDb::<D>::save_first_preprocess(&mut txn, spec.set().network, id.id, preprocess);

            // If this is the new key's first Batch, only create this TX once we verify all
            // all prior published `Batch`s
            let last_received = MainDb::<D>::last_received_batch(&txn, msg.network).unwrap();
            let handover_batch = MainDb::<D>::handover_batch(&txn, spec.set());
            if handover_batch.is_none() {
              MainDb::<D>::set_handover_batch(&mut txn, spec.set(), last_received);
              if last_received != 0 {
                // Decrease by 1, to get the ID of the Batch prior to this Batch
                let prior_sets_last_batch = last_received - 1;
                loop {
                  let successfully_verified = substrate::verify_published_batches::<D>(
                    &mut txn,
                    msg.network,
                    prior_sets_last_batch,
                  )
                  .await;
                  if successfully_verified == Some(prior_sets_last_batch) {
                    break;
                  }
                  sleep(Duration::from_secs(5)).await;
                }
              }
            }

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
            let handover_batch = MainDb::<D>::handover_batch(&txn, spec.set()).unwrap();
            let intended = Transaction::Batch(block.0, id.id);
            let mut res = vec![intended.clone()];
            if last_received > handover_batch {
              if let Some(last_verified) = MainDb::<D>::last_verified_batch(&txn, msg.network) {
                if last_verified < handover_batch {
                  res = vec![];
                }
              } else {
                res = vec![];
              }
            }

            if res.is_empty() {
              MainDb::<D>::queue_batch(&mut txn, spec.set(), intended);
            }

            res
          } else {
            vec![Transaction::BatchPreprocess(SignData {
              plan: id.id,
              attempt: id.attempt,
              data: preprocess,
              signed: Transaction::empty_signed(),
            })]
          }
        }
        coordinator::ProcessorMessage::BatchShare { id, share } => {
          vec![Transaction::BatchShare(SignData {
            plan: id.id,
            attempt: id.attempt,
            data: share.to_vec(),
            signed: Transaction::empty_signed(),
          })]
        }
      },
      ProcessorMessage::Substrate(inner_msg) => match inner_msg {
        processor_messages::substrate::ProcessorMessage::Batch { .. } => unreachable!(),
        processor_messages::substrate::ProcessorMessage::SignedBatch { .. } => {
          // We only reach here if this SignedBatch triggered the publication of a handover
          // Batch
          // Since the handover `Batch` was successfully published and verified, we no longer
          // have to worry about the above n+1 attack
          MainDb::<D>::take_queued_batches(&mut txn, spec.set())
        }
      },
    };

    // If this created transactions, publish them
    for mut tx in txs {
      log::trace!("processor message effected transaction {}", hex::encode(tx.hash()));

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
          // Ignores the result since we can't differentiate already in-mempool from
          // already on-chain from invalid
          // TODO: Don't ignore the result
          tributary.add_transaction(tx).await;
        }
        TransactionKind::Signed(_) => {
          log::trace!("getting next nonce for Tributary TX in response to processor message");

          let nonce = loop {
            let Some(nonce) =
              NonceDecider::<D>::nonce(&txn, genesis, &tx).expect("signed TX didn't have nonce")
            else {
              // This can be None if the following events occur, in order:
              // 1) We scanned the relevant transaction(s) in a Tributary block
              // 2) The processor was sent a message and responded
              // 3) The Tributary TXN has yet to be committed
              log::warn!("nonce has yet to be saved for processor-instigated transaction");
              sleep(Duration::from_millis(100)).await;
              continue;
            };
            break nonce;
          };
          tx.sign(&mut OsRng, genesis, key, nonce);

          publish_signed_transaction(&mut txn, tributary, tx).await;
        }
      }
    }
  }

  MainDb::<D>::save_handled_message(&mut txn, msg.network, msg.id);
  txn.commit();

  true
}

async fn handle_processor_messages<D: Db, Pro: Processors, P: P2p>(
  mut db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: Arc<Serai>,
  mut processors: Pro,
  network: NetworkId,
  mut new_tributary: mpsc::UnboundedReceiver<ActiveTributary<D, P>>,
) {
  let mut tributaries = HashMap::new();
  loop {
    match new_tributary.try_recv() {
      Ok(tributary) => {
        let set = tributary.spec.set();
        assert_eq!(set.network, network);
        tributaries.insert(set.session, tributary);
      }
      Err(mpsc::error::TryRecvError::Empty) => {}
      Err(mpsc::error::TryRecvError::Disconnected) => {
        panic!("handle_processor_messages new_tributary sender closed")
      }
    }

    // TODO: Check this ID is sane (last handled ID or expected next ID)
    let msg = processors.recv(network).await;
    if handle_processor_message(&mut db, &key, &serai, &tributaries, network, &msg).await {
      processors.ack(msg).await;
    }
  }
}

pub async fn handle_processors<D: Db, Pro: Processors, P: P2p>(
  db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: Arc<Serai>,
  processors: Pro,
  mut new_tributary: broadcast::Receiver<ActiveTributary<D, P>>,
) {
  let mut channels = HashMap::new();
  for network in serai_client::primitives::NETWORKS {
    if network == NetworkId::Serai {
      continue;
    }
    let (send, recv) = mpsc::unbounded_channel();
    tokio::spawn(handle_processor_messages(
      db.clone(),
      key.clone(),
      serai.clone(),
      processors.clone(),
      network,
      recv,
    ));
    channels.insert(network, send);
  }

  // Listen to new tributary events
  loop {
    let tributary = new_tributary.recv().await.unwrap();
    channels[&tributary.spec.set().network].send(tributary).unwrap();
  }
}

pub async fn run<D: Db, Pro: Processors, P: P2p>(
  raw_db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  p2p: P,
  processors: Pro,
  serai: Serai,
) {
  let serai = Arc::new(serai);

  let (new_tributary_spec_send, mut new_tributary_spec_recv) = mpsc::unbounded_channel();
  // Reload active tributaries from the database
  for spec in MainDb::<D>::active_tributaries(&raw_db).1 {
    new_tributary_spec_send.send(spec).unwrap();
  }

  // Handle new Substrate blocks
  tokio::spawn(crate::substrate::scan_task(
    raw_db.clone(),
    key.clone(),
    processors.clone(),
    serai.clone(),
    new_tributary_spec_send,
  ));

  // Handle the Tributaries

  // This should be large enough for an entire rotation of all tributaries
  // If it's too small, the coordinator fail to boot, which is a decent sanity check
  let (new_tributary, mut new_tributary_listener_1) = broadcast::channel(32);
  let new_tributary_listener_2 = new_tributary.subscribe();
  let new_tributary_listener_3 = new_tributary.subscribe();
  let new_tributary_listener_4 = new_tributary.subscribe();
  let new_tributary_listener_5 = new_tributary.subscribe();

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
          let new_tributary = new_tributary.clone();
          async move {
            add_tributary(raw_db, key, &processors, p2p, &new_tributary, spec).await;
          }
        });
      }
    }
  });

  // When we reach synchrony on an event requiring signing, send our preprocess for it
  let recognized_id = {
    let raw_db = raw_db.clone();
    let key = key.clone();

    let tributaries = Arc::new(RwLock::new(HashMap::new()));
    tokio::spawn({
      let tributaries = tributaries.clone();
      async move {
        loop {
          match new_tributary_listener_1.recv().await {
            Ok(tributary) => {
              tributaries.write().await.insert(tributary.spec.genesis(), tributary.tributary);
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {
              panic!("recognized_id lagged to handle new_tributary")
            }
            Err(broadcast::error::RecvError::Closed) => panic!("new_tributary sender closed"),
          }
        }
      }
    });

    move |network, genesis, id_type, id, nonce| {
      let mut raw_db = raw_db.clone();
      let key = key.clone();
      let tributaries = tributaries.clone();
      async move {
        // The transactions for these are fired before the preprocesses are actually
        // received/saved, creating a race between Tributary ack and the availability of all
        // Preprocesses
        // This waits until the necessary preprocess is available
        let get_preprocess = |raw_db, id| async move {
          loop {
            let Some(preprocess) = MainDb::<D>::first_preprocess(raw_db, network, id) else {
              sleep(Duration::from_millis(100)).await;
              continue;
            };
            return preprocess;
          }
        };

        let mut tx = match id_type {
          RecognizedIdType::Batch => Transaction::BatchPreprocess(SignData {
            plan: id,
            attempt: 0,
            data: get_preprocess(&raw_db, id).await,
            signed: Transaction::empty_signed(),
          }),

          RecognizedIdType::Plan => Transaction::SignPreprocess(SignData {
            plan: id,
            attempt: 0,
            data: get_preprocess(&raw_db, id).await,
            signed: Transaction::empty_signed(),
          }),
        };

        tx.sign(&mut OsRng, genesis, &key, nonce);

        let mut first = true;
        loop {
          if !first {
            sleep(Duration::from_millis(100)).await;
          }
          first = false;

          let tributaries = tributaries.read().await;
          let Some(tributary) = tributaries.get(&genesis) else {
            // This may happen if the task above is simply slow
            log::warn!("tributary we don't have yet came to consensus on an Batch");
            continue;
          };
          // This is safe to perform multiple times and solely needs atomicity within itself
          let mut txn = raw_db.txn();
          publish_signed_transaction(&mut txn, tributary, tx).await;
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
      new_tributary_listener_2,
    ));
  }

  // Spawn the heartbeat task, which will trigger syncing if there hasn't been a Tributary block
  // in a while (presumably because we're behind)
  tokio::spawn(p2p::heartbeat_tributaries_task(p2p.clone(), new_tributary_listener_3));

  // Handle P2P messages
  tokio::spawn(p2p::handle_p2p_task(
    Ristretto::generator() * key.deref(),
    p2p,
    new_tributary_listener_4,
  ));

  // Handle all messages from processors
  handle_processors(raw_db, key, serai, processors, new_tributary_listener_5).await;
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

  let db = serai_db::new_rocksdb(&env::var("DB_PATH").expect("path to DB wasn't specified"));

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
  let p2p = LibP2p::new();

  let processors = Arc::new(MessageQueue::from_env(Service::Coordinator));

  let serai = || async {
    loop {
      let Ok(serai) = Serai::new(&format!(
        "ws://{}:9944",
        serai_env::var("SERAI_HOSTNAME").expect("Serai hostname wasn't provided")
      ))
      .await
      else {
        log::error!("couldn't connect to the Serai node");
        sleep(Duration::from_secs(5)).await;
        continue;
      };
      log::info!("made initial connection to Serai node");
      return serai;
    }
  };
  run(db, key, p2p, processors, serai().await).await
}
