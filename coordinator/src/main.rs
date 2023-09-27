#![allow(unused_variables)]
#![allow(unreachable_code)]
#![allow(clippy::diverging_sub_expression)]

use core::{ops::Deref, future::Future};
use std::{
  sync::Arc,
  time::{SystemTime, Duration},
  collections::HashMap,
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

use serai_client::{primitives::NetworkId, Public, Serai};

use message_queue::{Service, client::MessageQueue};

use futures::stream::StreamExt;
use tokio::{
  sync::{RwLock, mpsc, broadcast},
  time::sleep,
};

use ::tributary::{ReadWrite, ProvidedError, TransactionKind, TransactionTrait, Block, Tributary};

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

#[cfg(test)]
pub mod tests;

#[derive(Clone)]
pub struct ActiveTributary<D: Db, P: P2p> {
  pub spec: TributarySpec,
  pub tributary: Arc<Tributary<D, Transaction, P>>,
}

// Adds a tributary into the specified HashMap
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
      processor_messages::CoordinatorMessage::KeyGen(
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
      ),
    )
    .await;

  tributaries
    .send(ActiveTributary { spec, tributary: Arc::new(tributary) })
    .map_err(|_| "all ActiveTributary recipients closed")
    .unwrap();
}

pub async fn scan_substrate<D: Db, Pro: Processors>(
  db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  processors: Pro,
  serai: Arc<Serai>,
  new_tributary_spec: mpsc::UnboundedSender<TributarySpec>,
) {
  log::info!("scanning substrate");

  let mut db = substrate::SubstrateDb::new(db);
  let mut next_substrate_block = db.next_block();

  let new_substrate_block_notifier = {
    let serai = &serai;
    move || async move {
      loop {
        match serai.newly_finalized_block().await {
          Ok(sub) => return sub,
          Err(e) => {
            log::error!("couldn't communicate with serai node: {e}");
            sleep(Duration::from_secs(5)).await;
          }
        }
      }
    }
  };
  let mut substrate_block_notifier = new_substrate_block_notifier().await;

  loop {
    // await the next block, yet if our notifier had an error, re-create it
    {
      let Ok(next_block) =
        tokio::time::timeout(Duration::from_secs(60), substrate_block_notifier.next()).await
      else {
        // Timed out, which may be because Serai isn't finalizing or may be some issue with the
        // notifier
        if serai.get_latest_block().await.map(|block| block.number()).ok() ==
          Some(next_substrate_block.saturating_sub(1))
        {
          log::info!("serai hasn't finalized a block in the last 60s...");
        } else {
          substrate_block_notifier = new_substrate_block_notifier().await;
        }
        continue;
      };

      // next_block is a Option<Result>
      if next_block.and_then(Result::ok).is_none() {
        substrate_block_notifier = new_substrate_block_notifier().await;
        continue;
      }
    }

    match substrate::handle_new_blocks(
      &mut db,
      &key,
      |db: &mut D, spec: TributarySpec| {
        log::info!("creating new tributary for {:?}", spec.set());

        // Save it to the database
        let mut txn = db.txn();
        MainDb::<D>::add_active_tributary(&mut txn, &spec);
        txn.commit();

        // If we reboot before this is read, the fact it was saved to the database means it'll be
        // handled on reboot
        new_tributary_spec.send(spec).unwrap();
      },
      &processors,
      &serai,
      &mut next_substrate_block,
    )
    .await
    {
      Ok(()) => {}
      Err(e) => {
        log::error!("couldn't communicate with serai node: {e}");
        sleep(Duration::from_secs(5)).await;
      }
    }
  }
}

pub(crate) trait RIDTrait<FRid>:
  Clone + Fn(NetworkId, [u8; 32], RecognizedIdType, [u8; 32], u32) -> FRid
{
}
impl<FRid, F: Clone + Fn(NetworkId, [u8; 32], RecognizedIdType, [u8; 32], u32) -> FRid>
  RIDTrait<FRid> for F
{
}

#[allow(clippy::type_complexity)]
pub(crate) async fn scan_tributaries<
  D: Db,
  Pro: Processors,
  P: P2p,
  FRid: Send + Future<Output = ()>,
  RID: 'static + Send + Sync + RIDTrait<FRid>,
>(
  raw_db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: RID,
  p2p: P,
  processors: Pro,
  serai: Arc<Serai>,
  mut new_tributary: broadcast::Receiver<ActiveTributary<D, P>>,
) {
  log::info!("scanning tributaries");

  loop {
    match new_tributary.recv().await {
      Ok(ActiveTributary { spec, tributary }) => {
        // For each Tributary, spawn a dedicated scanner task
        tokio::spawn({
          let raw_db = raw_db.clone();
          let key = key.clone();
          let recognized_id = recognized_id.clone();
          let p2p = p2p.clone();
          let processors = processors.clone();
          let serai = serai.clone();
          async move {
            let spec = &spec;
            let reader = tributary.reader();
            let mut tributary_db = tributary::TributaryDb::new(raw_db.clone());
            loop {
              // Obtain the next block notification now to prevent obtaining it immediately after
              // the next block occurs
              let next_block_notification = tributary.next_block_notification().await;

              tributary::scanner::handle_new_blocks::<_, _, _, _, _, _, P>(
                &mut tributary_db,
                &key,
                recognized_id.clone(),
                &processors,
                |set, tx| {
                  let serai = serai.clone();
                  async move {
                    loop {
                      match serai.publish(&tx).await {
                        Ok(_) => {
                          log::info!("set key pair for {set:?}");
                          break;
                        }
                        // This is assumed to be some ephemeral error due to the assumed fault-free
                        // creation
                        // TODO2: Differentiate connection errors from invariants
                        Err(e) => {
                          // Check if this failed because the keys were already set by someone else
                          if matches!(serai.get_keys(spec.set()).await, Ok(Some(_))) {
                            log::info!("another coordinator set key pair for {:?}", set);
                            break;
                          }

                          log::error!(
                            "couldn't connect to Serai node to publish set_keys TX: {:?}",
                            e
                          );
                          tokio::time::sleep(Duration::from_secs(10)).await;
                        }
                      }
                    }
                  }
                },
                spec,
                &reader,
              )
              .await;

              next_block_notification
                .await
                .map_err(|_| "")
                .expect("tributary dropped its notifications?");
            }
          }
        });
      }
      Err(broadcast::error::RecvError::Lagged(_)) => {
        panic!("scan_tributaries lagged to handle new_tributary")
      }
      Err(broadcast::error::RecvError::Closed) => panic!("new_tributary sender closed"),
    }
  }
}

pub async fn heartbeat_tributaries<D: Db, P: P2p>(
  p2p: P,
  mut new_tributary: broadcast::Receiver<ActiveTributary<D, P>>,
) {
  let ten_blocks_of_time =
    Duration::from_secs((10 * Tributary::<D, Transaction, P>::block_time()).into());

  let mut readers = vec![];
  loop {
    while let Ok(ActiveTributary { spec, tributary }) = {
      match new_tributary.try_recv() {
        Ok(tributary) => Ok(tributary),
        Err(broadcast::error::TryRecvError::Empty) => Err(()),
        Err(broadcast::error::TryRecvError::Lagged(_)) => {
          panic!("heartbeat_tributaries lagged to handle new_tributary")
        }
        Err(broadcast::error::TryRecvError::Closed) => panic!("new_tributary sender closed"),
      }
    } {
      readers.push(tributary.reader());
    }

    for tributary in &readers {
      let tip = tributary.tip();
      let block_time =
        SystemTime::UNIX_EPOCH + Duration::from_secs(tributary.time_of_block(&tip).unwrap_or(0));

      // Only trigger syncing if the block is more than a minute behind
      if SystemTime::now() > (block_time + Duration::from_secs(60)) {
        log::warn!("last known tributary block was over a minute ago");
        let mut msg = tip.to_vec();
        // Also include the timestamp so LibP2p doesn't flag this as an old message re-circulating
        let timestamp = SystemTime::now()
          .duration_since(SystemTime::UNIX_EPOCH)
          .expect("system clock is wrong")
          .as_secs();
        // Divide by the block time so if multiple parties send a Heartbeat, they're more likely to
        // overlap
        let time_unit = timestamp / u64::from(Tributary::<D, Transaction, P>::block_time());
        msg.extend(time_unit.to_le_bytes());
        P2p::broadcast(&p2p, P2pMessageKind::Heartbeat(tributary.genesis()), msg).await;
      }
    }

    // Only check once every 10 blocks of time
    sleep(ten_blocks_of_time).await;
  }
}

pub async fn handle_p2p<D: Db, P: P2p>(
  our_key: <Ristretto as Ciphersuite>::G,
  p2p: P,
  mut new_tributary: broadcast::Receiver<ActiveTributary<D, P>>,
) {
  let channels = Arc::new(RwLock::new(HashMap::new()));
  tokio::spawn({
    let p2p = p2p.clone();
    let channels = channels.clone();
    async move {
      loop {
        let tributary = new_tributary.recv().await.unwrap();
        let genesis = tributary.spec.genesis();

        let (send, mut recv) = mpsc::unbounded_channel();
        channels.write().await.insert(genesis, send);

        tokio::spawn({
          let p2p = p2p.clone();
          async move {
            loop {
              let mut msg: Message<P> = recv.recv().await.unwrap();
              match msg.kind {
                P2pMessageKind::KeepAlive => {}

                P2pMessageKind::Tributary(msg_genesis) => {
                  assert_eq!(msg_genesis, genesis);
                  log::trace!("handling message for tributary {:?}", tributary.spec.set());
                  if tributary.tributary.handle_message(&msg.msg).await {
                    P2p::broadcast(&p2p, msg.kind, msg.msg).await;
                  }
                }

                // TODO2: Rate limit this per timestamp
                // And/or slash on Heartbeat which justifies a response, since the node obviously
                // was offline and we must now use our bandwidth to compensate for them?
                P2pMessageKind::Heartbeat(msg_genesis) => {
                  assert_eq!(msg_genesis, genesis);
                  if msg.msg.len() != 40 {
                    log::error!("validator sent invalid heartbeat");
                    continue;
                  }

                  let p2p = p2p.clone();
                  let spec = tributary.spec.clone();
                  let reader = tributary.tributary.reader();
                  // Spawn a dedicated task as this may require loading large amounts of data from
                  // disk and take a notable amount of time
                  tokio::spawn(async move {
                    /*
                    // Have sqrt(n) nodes reply with the blocks
                    let mut responders = (tributary.spec.n() as f32).sqrt().floor() as u64;
                    // Try to have at least 3 responders
                    if responders < 3 {
                      responders = tributary.spec.n().min(3).into();
                    }
                    */

                    // Have up to three nodes respond
                    let responders = u64::from(spec.n().min(3));

                    // Decide which nodes will respond by using the latest block's hash as a
                    // mutually agreed upon entropy source
                    // This isn't a secure source of entropy, yet it's fine for this
                    let entropy = u64::from_le_bytes(reader.tip()[.. 8].try_into().unwrap());
                    // If n = 10, responders = 3, we want `start` to be 0 ..= 7
                    // (so the highest is 7, 8, 9)
                    // entropy % (10 + 1) - 3 = entropy % 8 = 0 ..= 7
                    let start =
                      usize::try_from(entropy % (u64::from(spec.n() + 1) - responders)).unwrap();
                    let mut selected = false;
                    for validator in
                      &spec.validators()[start .. (start + usize::try_from(responders).unwrap())]
                    {
                      if our_key == validator.0 {
                        selected = true;
                        break;
                      }
                    }
                    if !selected {
                      log::debug!("received heartbeat and not selected to respond");
                      return;
                    }

                    log::debug!("received heartbeat and selected to respond");

                    let mut latest = msg.msg[.. 32].try_into().unwrap();
                    while let Some(next) = reader.block_after(&latest) {
                      let mut res = reader.block(&next).unwrap().serialize();
                      res.extend(reader.commit(&next).unwrap());
                      // Also include the timestamp used within the Heartbeat
                      res.extend(&msg.msg[32 .. 40]);
                      p2p.send(msg.sender, P2pMessageKind::Block(spec.genesis()), res).await;
                      latest = next;
                    }
                  });
                }

                P2pMessageKind::Block(msg_genesis) => {
                  assert_eq!(msg_genesis, genesis);
                  let mut msg_ref: &[u8] = msg.msg.as_ref();
                  let Ok(block) = Block::<Transaction>::read(&mut msg_ref) else {
                    log::error!("received block message with an invalidly serialized block");
                    continue;
                  };
                  // Get just the commit
                  msg.msg.drain(.. (msg.msg.len() - msg_ref.len()));
                  msg.msg.drain((msg.msg.len() - 8) ..);

                  let res = tributary.tributary.sync_block(block, msg.msg).await;
                  log::debug!("received block from {:?}, sync_block returned {}", msg.sender, res);
                }
              }
            }
          }
        });
      }
    }
  });

  loop {
    let msg = p2p.receive().await;
    match msg.kind {
      P2pMessageKind::KeepAlive => {}
      P2pMessageKind::Tributary(genesis) => {
        if let Some(channel) = channels.read().await.get(&genesis) {
          channel.send(msg).unwrap();
        }
      }
      P2pMessageKind::Heartbeat(genesis) => {
        if let Some(channel) = channels.read().await.get(&genesis) {
          channel.send(msg).unwrap();
        }
      }
      P2pMessageKind::Block(genesis) => {
        if let Some(channel) = channels.read().await.get(&genesis) {
          channel.send(msg).unwrap();
        }
      }
    }
  }
}

async fn publish_signed_transaction<D: Db, P: P2p>(
  db: &mut D,
  tributary: &Tributary<D, Transaction, P>,
  tx: Transaction,
) {
  log::debug!("publishing transaction {}", hex::encode(tx.hash()));

  let mut txn = db.txn();
  let signer = if let TransactionKind::Signed(signed) = tx.kind() {
    let signer = signed.signer;

    // Safe as we should deterministically create transactions, meaning if this is already on-disk,
    // it's what we're saving now
    MainDb::<D>::save_signed_transaction(&mut txn, signed.nonce, tx);

    signer
  } else {
    panic!("non-signed transaction passed to publish_signed_transaction");
  };

  // If we're trying to publish 5, when the last transaction published was 3, this will delay
  // publication until the point in time we publish 4
  while let Some(tx) = MainDb::<D>::take_signed_transaction(
    &mut txn,
    tributary
      .next_nonce(signer)
      .await
      .expect("we don't have a nonce, meaning we aren't a participant on this tributary"),
  ) {
    // We should've created a valid transaction
    // This does assume publish_signed_transaction hasn't been called twice with the same
    // transaction, which risks a race condition on the validity of this assert
    // Our use case only calls this function sequentially
    assert!(tributary.add_transaction(tx).await, "created an invalid transaction");
  }
  txn.commit();
}

async fn handle_processor_messages<D: Db, Pro: Processors, P: P2p>(
  mut db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: Arc<Serai>,
  mut processors: Pro,
  tributary: ActiveTributary<D, P>,
  mut recv: mpsc::UnboundedReceiver<processors::Message>,
) {
  let mut db_clone = db.clone(); // Enables cloning the DB while we have a txn
  let pub_key = Ristretto::generator() * key.deref();

  let ActiveTributary { spec, tributary } = tributary;
  let genesis = spec.genesis();

  loop {
    let msg: processors::Message = recv.recv().await.unwrap();

    if !MainDb::<D>::handled_message(&db, msg.id) {
      let mut txn = db.txn();

      // TODO: We probably want to NOP here, not panic?
      // TODO: We do have to track produced Batches in order to ensure their integrity
      let my_i = spec.i(pub_key).expect("processor message for network we aren't a validator in");

      let tx = match msg.msg.clone() {
        ProcessorMessage::KeyGen(inner_msg) => match inner_msg {
          key_gen::ProcessorMessage::Commitments { id, commitments } => {
            Some(Transaction::DkgCommitments(id.attempt, commitments, Transaction::empty_signed()))
          }
          key_gen::ProcessorMessage::Shares { id, mut shares } => {
            // Create a MuSig-based machine to inform Substrate of this key generation
            let nonces = crate::tributary::dkg_confirmation_nonces(&key, &spec, id.attempt);

            let mut tx_shares = Vec::with_capacity(shares.len());
            for i in 1 ..= spec.n() {
              let i = Participant::new(i).unwrap();
              if i == my_i {
                continue;
              }
              tx_shares.push(
                shares.remove(&i).expect("processor didn't send share for another validator"),
              );
            }

            Some(Transaction::DkgShares {
              attempt: id.attempt,
              shares: tx_shares,
              confirmation_nonces: nonces,
              signed: Transaction::empty_signed(),
            })
          }
          key_gen::ProcessorMessage::GeneratedKeyPair { id, substrate_key, network_key } => {
            assert_eq!(
              id.set.network, msg.network,
              "processor claimed to be a different network than it was for GeneratedKeyPair",
            );
            // TODO: Also check the other KeyGenId fields

            // Tell the Tributary the key pair, get back the share for the MuSig
            // signature
            let share = crate::tributary::generated_key_pair::<D>(
              &mut txn,
              &key,
              &spec,
              &(Public(substrate_key), network_key.try_into().unwrap()),
              id.attempt,
            );

            match share {
              Ok(share) => {
                Some(Transaction::DkgConfirmed(id.attempt, share, Transaction::empty_signed()))
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
              MainDb::<D>::save_first_preprocess(&mut txn, id.id, preprocess);

              None
            } else {
              Some(Transaction::SignPreprocess(SignData {
                plan: id.id,
                attempt: id.attempt,
                data: preprocess,
                signed: Transaction::empty_signed(),
              }))
            }
          }
          sign::ProcessorMessage::Share { id, share } => Some(Transaction::SignShare(SignData {
            plan: id.id,
            attempt: id.attempt,
            data: share,
            signed: Transaction::empty_signed(),
          })),
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
            let signed = SchnorrSignature::sign(&key, r, tx.sign_completed_challenge());
            match &mut tx {
              Transaction::SignCompleted { signature, .. } => {
                *signature = signed;
              }
              _ => unreachable!(),
            }
            Some(tx)
          }
        },
        ProcessorMessage::Coordinator(inner_msg) => match inner_msg {
          coordinator::ProcessorMessage::SubstrateBlockAck { network, block, plans } => {
            assert_eq!(
              network, msg.network,
              "processor claimed to be a different network than it was for SubstrateBlockAck",
            );

            // TODO: This needs to be scoped per multisig
            TributaryDb::<D>::set_plan_ids(&mut txn, genesis, block, &plans);

            Some(Transaction::SubstrateBlock(block))
          }
          coordinator::ProcessorMessage::BatchPreprocess { id, block, preprocess } => {
            log::info!(
              "informed of batch (sign ID {}, attempt {}) for block {}",
              hex::encode(id.id),
              id.attempt,
              hex::encode(block),
            );
            // If this is the first attempt instance, wait until we synchronize around
            // the batch first
            if id.attempt == 0 {
              MainDb::<D>::save_first_preprocess(&mut txn, id.id, preprocess);

              Some(Transaction::Batch(block.0, id.id))
            } else {
              Some(Transaction::BatchPreprocess(SignData {
                plan: id.id,
                attempt: id.attempt,
                data: preprocess,
                signed: Transaction::empty_signed(),
              }))
            }
          }
          coordinator::ProcessorMessage::BatchShare { id, share } => {
            Some(Transaction::BatchShare(SignData {
              plan: id.id,
              attempt: id.attempt,
              data: share.to_vec(),
              signed: Transaction::empty_signed(),
            }))
          }
        },
        ProcessorMessage::Substrate(inner_msg) => match inner_msg {
          processor_messages::substrate::ProcessorMessage::Update { batch } => {
            assert_eq!(
              batch.batch.network, msg.network,
              "processor sent us a batch for a different network than it was for",
            );
            // TODO: Check this key's key pair's substrate key is authorized to publish
            // batches

            // Save this batch to the disk
            MainDb::<D>::save_batch(&mut txn, batch);

            /*
              Use a dedicated task to publish batches due to the latency potentially
              incurred.

              This does not guarantee the batch has actually been published when the
              message is `ack`ed to message-queue. Accordingly, if we reboot, these
              batches would be dropped (as we wouldn't see the `Update` again, triggering
              our re-attempt to publish).

              The solution to this is to have the task try not to publish the batch which
              caused it to be spawned, yet all saved batches which have yet to published.
              This does risk having multiple tasks trying to publish all pending batches,
              yet these aren't notably complex.
            */
            tokio::spawn({
              let db = db_clone.clone();
              let serai = serai.clone();
              let network = msg.network;
              async move {
                // Since we have a new batch, publish all batches yet to be published to
                // Serai
                // This handles the edge-case where batch n+1 is signed before batch n is
                while let Some(batch) = {
                  // Get the next-to-execute batch ID
                  let next = {
                    let mut first = true;
                    loop {
                      if !first {
                        log::error!(
                          "{} {network:?}",
                          "couldn't connect to Serai node to get the next batch ID for",
                        );
                        tokio::time::sleep(Duration::from_secs(5)).await;
                      }
                      first = false;

                      let Ok(latest_block) = serai.get_latest_block().await else {
                        continue;
                      };
                      let Ok(last) =
                        serai.get_last_batch_for_network(latest_block.hash(), network).await
                      else {
                        continue;
                      };
                      break if let Some(last) = last { last + 1 } else { 0 };
                    }
                  };

                  // If we have this batch, attempt to publish it
                  MainDb::<D>::batch(&db, network, next)
                } {
                  let id = batch.batch.id;
                  let block = batch.batch.block;

                  let tx = Serai::execute_batch(batch);
                  // This publish may fail if this transactions already exists in the
                  // mempool, which is possible, or if this batch was already executed
                  // on-chain
                  // Either case will have eventual resolution and be handled by the
                  // above check on if this batch should execute
                  if serai.publish(&tx).await.is_ok() {
                    log::info!("published batch {network:?} {id} (block {})", hex::encode(block));
                  }
                }
              }
            });

            None
          }
        },
      };

      // If this created a transaction, publish it
      if let Some(mut tx) = tx {
        log::trace!("processor message effected transaction {}", hex::encode(tx.hash()));

        match tx.kind() {
          TransactionKind::Provided(_) => {
            log::trace!("providing transaction {}", hex::encode(tx.hash()));
            let res = tributary.provide_transaction(tx).await;
            if !(res.is_ok() || (res == Err(ProvidedError::AlreadyProvided))) {
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
                // This can be None if:
                // 1) We scanned the relevant transaction(s) in a Tributary block
                // 2) The processor was sent a message and responded
                // 3) The Tributary TXN has yet to be committed
                log::warn!("nonce has yet to be saved for processor-instigated transaction");
                sleep(Duration::from_millis(100)).await;
                continue;
              };
              break nonce;
            };
            tx.sign(&mut OsRng, genesis, &key, nonce);

            publish_signed_transaction(&mut db_clone, &tributary, tx).await;
          }
        }
      }

      MainDb::<D>::save_handled_message(&mut txn, msg.id);
      txn.commit();
    }

    processors.ack(msg).await;
  }
}

pub async fn handle_processors<D: Db, Pro: Processors, P: P2p>(
  db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: Arc<Serai>,
  mut processors: Pro,
  mut new_tributary: broadcast::Receiver<ActiveTributary<D, P>>,
) {
  let channels = Arc::new(RwLock::new(HashMap::new()));
  // Listen to new tributary events
  tokio::spawn({
    let db = db.clone();
    let processors = processors.clone();
    let channels = channels.clone();
    async move {
      loop {
        let channels = channels.clone();
        let tributary = new_tributary.recv().await.unwrap();

        let (send, recv) = mpsc::unbounded_channel();
        // TODO: Support multisig rotation (not per-Tributary yet per-network?)
        channels.write().await.insert(tributary.spec.set().network, send);

        // For each new tributary, spawn a dedicated task to handle its messages from the processor
        // TODO: Redo per network, not per tributary
        tokio::spawn(handle_processor_messages(
          db.clone(),
          key.clone(),
          serai.clone(),
          processors.clone(),
          tributary,
          recv,
        ));
      }
    }
  });

  // Dispatch task
  let mut last_msg = None;
  loop {
    // TODO: We dispatch this to an async task per-processor, yet we don't move to the next message
    // yet as all processor messages are shoved into a global queue.
    // Modify message-queue to offer per-sender queues, not per-receiver.
    // Alternatively, a peek method with local delineation of handled messages would work.

    let msg = processors.recv().await;
    if last_msg == Some(msg.id) {
      sleep(Duration::from_secs(1)).await;
      continue;
    }
    last_msg = Some(msg.id);

    // TODO: Race conditions with above tributary availability?
    // TODO: How does this hold up to multisig rotation?
    if let Some(channel) = channels.read().await.get(&msg.network) {
      channel.send(msg).unwrap();
    } else {
      log::warn!("received processor message for network we don't have a channel for");
    }
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
  tokio::spawn(scan_substrate(
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
        add_tributary(
          raw_db.clone(),
          key.clone(),
          &processors,
          p2p.clone(),
          &new_tributary,
          spec.clone(),
        )
        .await;
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
            let Some(preprocess) = MainDb::<D>::first_preprocess(raw_db, id) else {
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

        let tributaries = tributaries.read().await;
        let Some(tributary) = tributaries.get(&genesis) else {
          // TODO: This may happen if the task above is simply slow
          panic!("tributary we don't have came to consensus on an Batch");
        };
        publish_signed_transaction(&mut raw_db, tributary, tx).await;
      }
    }
  };

  // Handle new blocks for each Tributary
  {
    let raw_db = raw_db.clone();
    tokio::spawn(scan_tributaries(
      raw_db,
      key.clone(),
      recognized_id,
      p2p.clone(),
      processors.clone(),
      serai.clone(),
      new_tributary_listener_2,
    ));
  }

  // Spawn the heartbeat task, which will trigger syncing if there hasn't been a Tributary block
  // in a while (presumably because we're behind)
  tokio::spawn(heartbeat_tributaries(p2p.clone(), new_tributary_listener_3));

  // Handle P2P messages
  tokio::spawn(handle_p2p(Ristretto::generator() * key.deref(), p2p, new_tributary_listener_4));

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
