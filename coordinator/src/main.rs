use core::{ops::Deref, future::Future};
use std::{
  sync::Arc,
  time::{SystemTime, Duration},
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
use substrate::SubstrateDb;

#[cfg(test)]
pub mod tests;

#[derive(Clone)]
pub struct ActiveTributary<D: Db, P: P2p> {
  pub spec: TributarySpec,
  pub tributary: Arc<Tributary<D, Transaction, P>>,
}

// Creates a new tributary and sends it to all listeners.
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

pub async fn scan_substrate<D: Db, Pro: Processors>(
  db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  processors: Pro,
  serai: Arc<Serai>,
  new_tributary_spec: mpsc::UnboundedSender<TributarySpec>,
) {
  log::info!("scanning substrate");

  let mut db = SubstrateDb::new(db);
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
                          if let Ok(latest) = serai.get_latest_block_hash().await {
                            // Check if this failed because the keys were already set by someone
                            // else
                            if matches!(serai.get_keys(spec.set(), latest).await, Ok(Some(_))) {
                              log::info!("another coordinator set key pair for {:?}", set);
                              break;
                            }

                            // The above block may return false if the keys have been pruned from
                            // the state
                            // Check if this session is no longer the latest session, meaning it at
                            // some point did set keys, and we're just operating off very
                            // historical data
                            if let Ok(Some(current_session)) =
                              serai.get_session(spec.set().network, latest).await
                            {
                              if current_session.0 > spec.set().session.0 {
                                log::warn!(
                                  "trying to set keys for a set which isn't the latest {:?}",
                                  set
                                );
                                break;
                              }
                            }
                          }

                          log::error!(
                            "couldn't connect to Serai node to publish set_keys TX: {:?}",
                            e
                          );
                          sleep(Duration::from_secs(10)).await;
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
    while let Ok(ActiveTributary { spec: _, tributary }) = {
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

/// Verifies `Batch`s which have already been indexed from Substrate.
async fn verify_published_batches<D: Db>(
  txn: &mut D::Transaction<'_>,
  network: NetworkId,
  optimistic_up_to: u32,
) -> Option<u32> {
  let last = MainDb::<D>::last_verified_batch(txn, network);
  for id in last.map(|last| last + 1).unwrap_or(0) ..= optimistic_up_to {
    let Some(on_chain) = SubstrateDb::<D>::batch_instructions_hash(txn, network, id) else {
      break;
    };
    let off_chain = MainDb::<D>::expected_batch(txn, network, id).unwrap();
    if on_chain != off_chain {
      // Halt operations on this network and spin, as this is a critical fault
      loop {
        log::error!(
          "{}! network: {:?} id: {} off-chain: {} on-chain: {}",
          "on-chain batch doesn't match off-chain",
          network,
          id,
          hex::encode(off_chain),
          hex::encode(on_chain),
        );
        sleep(Duration::from_secs(60)).await;
      }
    }
    MainDb::<D>::save_last_verified_batch(txn, network, id);
  }

  MainDb::<D>::last_verified_batch(txn, network)
}

async fn handle_processor_messages<D: Db, Pro: Processors, P: P2p>(
  mut db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: Arc<Serai>,
  mut processors: Pro,
  network: NetworkId,
  mut new_tributary: mpsc::UnboundedReceiver<ActiveTributary<D, P>>,
) {
  let mut db_clone = db.clone(); // Enables cloning the DB while we have a txn
  let pub_key = Ristretto::generator() * key.deref();

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

    if !MainDb::<D>::handled_message(&db, msg.network, msg.id) {
      let mut txn = db.txn();

      let relevant_tributary = match &msg.msg {
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
            // them all

            for tributary in tributaries.values() {
              // TODO: This needs to be scoped per multisig
              TributaryDb::<D>::set_plan_ids(&mut txn, tributary.spec.genesis(), *block, plans);

              let tx = Transaction::SubstrateBlock(*block);
              log::trace!("processor message effected transaction {}", hex::encode(tx.hash()));
              log::trace!("providing transaction {}", hex::encode(tx.hash()));
              let res = tributary.tributary.provide_transaction(tx).await;
              if !(res.is_ok() || (res == Err(ProvidedError::AlreadyProvided))) {
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
            verify_published_batches::<D>(&mut txn, msg.network, this_batch_id).await;

            None
          }
          // If this is a new Batch, immediately publish it (if we can)
          processor_messages::substrate::ProcessorMessage::SignedBatch { batch } => {
            assert_eq!(
              batch.batch.network, msg.network,
              "processor sent us a signed batch for a different network than it was for",
            );
            // TODO: Check this key's key pair's substrate key is authorized to publish batches

            log::debug!("received batch {:?} {}", batch.batch.network, batch.batch.id);

            // Save this batch to the disk
            MainDb::<D>::save_batch(&mut txn, batch.clone());

            // Get the next-to-execute batch ID
            async fn get_next(serai: &Serai, network: NetworkId) -> u32 {
              let mut first = true;
              loop {
                if !first {
                  log::error!(
                    "{} {network:?}",
                    "couldn't connect to Serai node to get the next batch ID for",
                  );
                  sleep(Duration::from_secs(5)).await;
                }
                first = false;

                let Ok(latest_block) = serai.get_latest_block().await else {
                  continue;
                };
                let Ok(last) = serai.get_last_batch_for_network(latest_block.hash(), network).await
                else {
                  continue;
                };
                break if let Some(last) = last { last + 1 } else { 0 };
              }
            }
            let mut next = get_next(&serai, network).await;

            // Since we have a new batch, publish all batches yet to be published to Serai
            // This handles the edge-case where batch n+1 is signed before batch n is
            let mut batches = VecDeque::new();
            while let Some(batch) = MainDb::<D>::batch(&txn, network, next) {
              batches.push_back(batch);
              next += 1;
            }

            while let Some(batch) = batches.pop_front() {
              // If this Batch should no longer be published, continue
              if get_next(&serai, network).await > batch.batch.id {
                continue;
              }

              let tx = Serai::execute_batch(batch.clone());
              log::debug!(
                "attempting to publish batch {:?} {}",
                batch.batch.network,
                batch.batch.id,
              );
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

      // If there's a relevant Tributary...
      if let Some(relevant_tributary) = relevant_tributary {
        // Make sure we have it
        // Per the reasoning above, we only return a Tributary as relevant if we're a participant
        // Accordingly, we do *need* to have this Tributary now to handle it UNLESS the Tributary
        // has already completed and this is simply an old message
        // TODO: Check if the Tributary has already been completed
        let Some(ActiveTributary { spec, tributary }) = tributaries.get(&relevant_tributary) else {
          // Since we don't, sleep for a fraction of a second and move to the next loop iteration
          // At the start of the loop, we'll check for new tributaries, making this eventually
          // resolve
          sleep(Duration::from_millis(100)).await;
          continue;
        };

        let genesis = spec.genesis();

        let tx = match msg.msg.clone() {
          ProcessorMessage::KeyGen(inner_msg) => match inner_msg {
            key_gen::ProcessorMessage::Commitments { id, commitments } => Some(
              Transaction::DkgCommitments(id.attempt, commitments, Transaction::empty_signed()),
            ),
            key_gen::ProcessorMessage::Shares { id, mut shares } => {
              // Create a MuSig-based machine to inform Substrate of this key generation
              let nonces = crate::tributary::dkg_confirmation_nonces(&key, spec, id.attempt);

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
              // TODO2: Also check the other KeyGenId fields

              // Tell the Tributary the key pair, get back the share for the MuSig signature
              let share = crate::tributary::generated_key_pair::<D>(
                &mut txn,
                &key,
                spec,
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
                MainDb::<D>::save_first_preprocess(&mut txn, network, id.id, preprocess);

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
                if (spec.set().session.0 != 0) && (!MainDb::<D>::did_handover(&txn, spec.set())) {
                  let last_received = MainDb::<D>::last_received_batch(&txn, msg.network);
                  if let Some(last_received) = last_received {
                    // Decrease by 1, to get the ID of the Batch prior to this Batch
                    let prior_sets_last_batch = last_received - 1;
                    loop {
                      let successfully_verified =
                        verify_published_batches::<D>(&mut txn, msg.network, prior_sets_last_batch)
                          .await;
                      if successfully_verified == Some(prior_sets_last_batch) {
                        break;
                      }
                      sleep(Duration::from_secs(5)).await;
                    }
                  }
                  MainDb::<D>::set_did_handover(&mut txn, spec.set());
                }

                // TODO: There is a race condition here. We may verify all `Batch`s from the prior
                // set, start signing the handover Batch `n`, start signing `n+1`, have `n+1`
                // signed before `n` (or at the same time), yet then the prior set forges a
                // malicious Batch `n`.
                //
                // The malicious Batch `n` would be publishable to Serai, as Serai can't
                // distinguish what's intended to be a handover `Batch`, yet then anyone could
                // publish the new set's `n+1`, causing their acceptance of the handover.

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
            processor_messages::substrate::ProcessorMessage::Batch { .. } => unreachable!(),
            processor_messages::substrate::ProcessorMessage::SignedBatch { .. } => unreachable!(),
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
                let Some(nonce) = NonceDecider::<D>::nonce(&txn, genesis, &tx)
                  .expect("signed TX didn't have nonce")
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

              publish_signed_transaction(&mut db_clone, tributary, tx).await;
            }
          }
        }
      }

      MainDb::<D>::save_handled_message(&mut txn, msg.network, msg.id);
      txn.commit();
    }

    processors.ack(msg).await;
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
