#![allow(unused_variables)]
#![allow(unreachable_code)]
#![allow(clippy::diverging_sub_expression)]

use core::{ops::Deref, future::Future};
use std::{
  sync::Arc,
  time::{SystemTime, Duration},
  collections::{VecDeque, HashMap},
};

use zeroize::{Zeroize, Zeroizing};
use rand_core::OsRng;

use ciphersuite::{group::ff::PrimeField, Ciphersuite, Ristretto};

use serai_db::{DbTxn, Db};
use serai_env as env;

use serai_client::{primitives::NetworkId, Public, Serai};

use message_queue::{Service, client::MessageQueue};

use tokio::{sync::RwLock, time::sleep};

use ::tributary::{
  ReadWrite, ProvidedError, TransactionKind, TransactionTrait, Block, Tributary, TributaryReader,
};

mod tributary;
#[rustfmt::skip]
use crate::tributary::{TributarySpec, SignData, Transaction, TributaryDb, scanner::RecognizedIdType};

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

lazy_static::lazy_static! {
  // This is a static to satisfy lifetime expectations
  static ref NEW_TRIBUTARIES: RwLock<VecDeque<TributarySpec>> = RwLock::new(VecDeque::new());
}

pub struct ActiveTributary<D: Db, P: P2p> {
  pub spec: TributarySpec,
  pub tributary: Arc<RwLock<Tributary<D, Transaction, P>>>,
}

type Tributaries<D, P> = HashMap<[u8; 32], ActiveTributary<D, P>>;

// Adds a tributary into the specified HahMap
async fn add_tributary<D: Db, P: P2p>(
  db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  p2p: P,
  tributaries: &mut Tributaries<D, P>,
  spec: TributarySpec,
) -> TributaryReader<D, Transaction> {
  log::info!("adding tributary {:?}", spec.set());

  let tributary = Tributary::<_, Transaction, _>::new(
    // TODO2: Use a db on a distinct volume
    db,
    spec.genesis(),
    spec.start_time(),
    key,
    spec.validators(),
    p2p,
  )
  .await
  .unwrap();

  let reader = tributary.reader();

  tributaries.insert(
    tributary.genesis(),
    ActiveTributary { spec, tributary: Arc::new(RwLock::new(tributary)) },
  );

  reader
}

pub async fn scan_substrate<D: Db, Pro: Processors>(
  db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  processors: Pro,
  serai: Arc<Serai>,
) {
  log::info!("scanning substrate");

  let mut db = substrate::SubstrateDb::new(db);
  let mut next_substrate_block = db.next_block();

  loop {
    match substrate::handle_new_blocks(
      &mut db,
      &key,
      |db: &mut D, spec: TributarySpec| {
        log::info!("creating new tributary for {:?}", spec.set());

        // Save it to the database
        MainDb::new(db).add_active_tributary(&spec);

        // Add it to the queue
        // If we reboot before this is read from the queue, the fact it was saved to the database
        // means it'll be handled on reboot
        async {
          NEW_TRIBUTARIES.write().await.push_back(spec);
        }
      },
      &processors,
      &serai,
      &mut next_substrate_block,
    )
    .await
    {
      // TODO2: Should this use a notification system for new blocks?
      // Right now it's sleeping for half the block time.
      Ok(()) => sleep(Duration::from_secs(3)).await,
      Err(e) => {
        log::error!("couldn't communicate with serai node: {e}");
        sleep(Duration::from_secs(5)).await;
      }
    }
  }
}

#[allow(clippy::type_complexity)]
pub async fn scan_tributaries<
  D: Db,
  Pro: Processors,
  P: P2p,
  FRid: Future<Output = Vec<[u8; 32]>>,
  RID: Clone + Fn(NetworkId, [u8; 32], RecognizedIdType, [u8; 32]) -> FRid,
>(
  raw_db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id: RID,
  p2p: P,
  processors: Pro,
  serai: Arc<Serai>,
  tributaries: Arc<RwLock<Tributaries<D, P>>>,
) {
  log::info!("scanning tributaries");

  let mut tributary_readers = vec![];
  for ActiveTributary { spec, tributary } in tributaries.read().await.values() {
    tributary_readers.push((spec.clone(), tributary.read().await.reader()));
  }

  // Handle new Tributary blocks
  let mut tributary_db = tributary::TributaryDb::new(raw_db.clone());
  loop {
    // The following handle_new_blocks function may take an arbitrary amount of time
    // Accordingly, it may take a long time to acquire a write lock on the tributaries table
    // By definition of NEW_TRIBUTARIES, we allow tributaries to be added almost immediately,
    // meaning the Substrate scanner won't become blocked on this
    {
      let mut new_tributaries = NEW_TRIBUTARIES.write().await;
      while let Some(spec) = new_tributaries.pop_front() {
        let reader = add_tributary(
          raw_db.clone(),
          key.clone(),
          p2p.clone(),
          // This is a short-lived write acquisition, which is why it should be fine
          &mut *tributaries.write().await,
          spec.clone(),
        )
        .await;

        tributary_readers.push((spec, reader));
      }
    }

    for (spec, reader) in &tributary_readers {
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
                // TODO: Differentiate connection errors from invariants
                Err(e) => {
                  // Check if this failed because the keys were already set by someone else
                  if matches!(serai.get_keys(spec.set()).await, Ok(Some(_))) {
                    log::info!("other party set key pair for {:?}", set);
                    break;
                  }

                  log::error!("couldn't connect to Serai node to publish set_keys TX: {:?}", e);
                  tokio::time::sleep(Duration::from_secs(10)).await;
                }
              }
            }
          }
        },
        spec,
        reader,
      )
      .await;
    }

    // Sleep for half the block time
    // TODO2: Should we define a notification system for when a new block occurs?
    sleep(Duration::from_secs((Tributary::<D, Transaction, P>::block_time() / 2).into())).await;
  }
}

pub async fn heartbeat_tributaries<D: Db, P: P2p>(
  p2p: P,
  tributaries: Arc<RwLock<Tributaries<D, P>>>,
) {
  let ten_blocks_of_time =
    Duration::from_secs((10 * Tributary::<D, Transaction, P>::block_time()).into());

  loop {
    for ActiveTributary { spec: _, tributary } in tributaries.read().await.values() {
      let tributary = tributary.read().await;
      let tip = tributary.tip().await;
      let block_time = SystemTime::UNIX_EPOCH +
        Duration::from_secs(tributary.reader().time_of_block(&tip).unwrap_or(0));

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
  tributaries: Arc<RwLock<Tributaries<D, P>>>,
) {
  loop {
    let mut msg = p2p.receive().await;
    match msg.kind {
      P2pMessageKind::KeepAlive => {}

      P2pMessageKind::Tributary(genesis) => {
        let tributaries = tributaries.read().await;
        let Some(tributary) = tributaries.get(&genesis) else {
          log::debug!("received p2p message for unknown network");
          continue;
        };

        log::trace!("handling message for tributary {:?}", tributary.spec.set());
        if tributary.tributary.read().await.handle_message(&msg.msg).await {
          P2p::broadcast(&p2p, msg.kind, msg.msg).await;
        }
      }

      // TODO2: Rate limit this per timestamp
      P2pMessageKind::Heartbeat(genesis) => {
        if msg.msg.len() != 40 {
          log::error!("validator sent invalid heartbeat");
          continue;
        }

        let tributaries = tributaries.read().await;
        let Some(tributary) = tributaries.get(&genesis) else {
          log::debug!("received heartbeat message for unknown network");
          continue;
        };
        let tributary_read = tributary.tributary.read().await;

        /*
        // Have sqrt(n) nodes reply with the blocks
        let mut responders = (tributary.spec.n() as f32).sqrt().floor() as u64;
        // Try to have at least 3 responders
        if responders < 3 {
          responders = tributary.spec.n().min(3).into();
        }
        */

        // Have up to three nodes respond
        let responders = u64::from(tributary.spec.n().min(3));

        // Decide which nodes will respond by using the latest block's hash as a mutually agreed
        // upon entropy source
        // This isn't a secure source of entropy, yet it's fine for this
        let entropy = u64::from_le_bytes(tributary_read.tip().await[.. 8].try_into().unwrap());
        // If n = 10, responders = 3, we want start to be 0 ..= 7 (so the highest is 7, 8, 9)
        // entropy % (10 + 1) - 3 = entropy % 8 = 0 ..= 7
        let start =
          usize::try_from(entropy % (u64::from(tributary.spec.n() + 1) - responders)).unwrap();
        let mut selected = false;
        for validator in
          &tributary.spec.validators()[start .. (start + usize::try_from(responders).unwrap())]
        {
          if our_key == validator.0 {
            selected = true;
            break;
          }
        }
        if !selected {
          log::debug!("received heartbeat and not selected to respond");
          continue;
        }

        log::debug!("received heartbeat and selected to respond");

        let reader = tributary_read.reader();
        drop(tributary_read);

        let mut latest = msg.msg[.. 32].try_into().unwrap();
        while let Some(next) = reader.block_after(&latest) {
          let mut res = reader.block(&next).unwrap().serialize();
          res.extend(reader.commit(&next).unwrap());
          // Also include the timestamp used within the Heartbeat
          res.extend(&msg.msg[32 .. 40]);
          p2p.send(msg.sender, P2pMessageKind::Block(tributary.spec.genesis()), res).await;
          latest = next;
        }
      }

      P2pMessageKind::Block(genesis) => {
        let mut msg_ref: &[u8] = msg.msg.as_ref();
        let Ok(block) = Block::<Transaction>::read(&mut msg_ref) else {
          log::error!("received block message with an invalidly serialized block");
          continue;
        };
        // Get just the commit
        msg.msg.drain(.. (msg.msg.len() - msg_ref.len()));
        msg.msg.drain((msg.msg.len() - 8) ..);

        // Spawn a dedicated task to add this block, as it may take a notable amount of time
        // While we could use a long-lived task to add each block, that task would only add one
        // block at a time *across all tributaries*
        // We either need:
        // 1) One task per tributary
        // 2) Background tasks
        // 3) For sync_block to return instead of waiting for provided transactions which are
        //    missing
        // sync_block waiting is preferable since we know the block is valid by its commit, meaning
        // we are the node behind
        // As for 1/2, 1 may be preferable since this message may frequently occur
        // This is suitably performant, as tokio HTTP servers will even spawn a new task per
        // connection
        // In order to reduce congestion though, we should at least check if we take value from
        // this message before running spawn
        // TODO2
        tokio::spawn({
          let tributaries = tributaries.clone();
          async move {
            let tributaries = tributaries.read().await;
            let Some(tributary) = tributaries.get(&genesis) else {
              log::debug!("received block message for unknown network");
              return;
            };

            let res = tributary.tributary.read().await.sync_block(block, msg.msg).await;
            log::debug!("received block from {:?}, sync_block returned {}", msg.sender, res);
          }
        });
      }
    }
  }
}

pub async fn publish_transaction<D: Db, P: P2p>(
  tributary: &Tributary<D, Transaction, P>,
  tx: Transaction,
) {
  log::debug!("publishing transaction {}", hex::encode(tx.hash()));
  if let TransactionKind::Signed(signed) = tx.kind() {
    if tributary
      .next_nonce(signed.signer)
      .await
      .expect("we don't have a nonce, meaning we aren't a participant on this tributary") >
      signed.nonce
    {
      log::warn!("we've already published this transaction. this should only appear on reboot");
    } else {
      // We should've created a valid transaction
      assert!(tributary.add_transaction(tx).await, "created an invalid transaction");
    }
  } else {
    panic!("non-signed transaction passed to publish_transaction");
  }
}

pub async fn handle_processors<D: Db, Pro: Processors, P: P2p>(
  mut db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: Arc<Serai>,
  mut processors: Pro,
  tributaries: Arc<RwLock<Tributaries<D, P>>>,
) {
  let pub_key = Ristretto::generator() * key.deref();

  loop {
    let msg = processors.recv().await;

    // TODO2: This is slow, and only works as long as a network only has a single Tributary
    // (which means there's a lack of multisig rotation)
    let spec = {
      let mut spec = None;
      for tributary in tributaries.read().await.values() {
        if tributary.spec.set().network == msg.network {
          spec = Some(tributary.spec.clone());
          break;
        }
      }
      spec.unwrap()
    };

    let genesis = spec.genesis();
    // TODO: We probably want to NOP here, not panic?
    let my_i = spec.i(pub_key).expect("processor message for network we aren't a validator in");

    let tx = match msg.msg.clone() {
      ProcessorMessage::KeyGen(inner_msg) => match inner_msg {
        key_gen::ProcessorMessage::Commitments { id, commitments } => {
          Some(Transaction::DkgCommitments(id.attempt, commitments, Transaction::empty_signed()))
        }
        key_gen::ProcessorMessage::Shares { id, shares } => {
          // Create a MuSig-based machine to inform Substrate of this key generation
          // DkgConfirmer has a TODO noting it's only secure for a single usage, yet this ensures
          // the TODO is resolved before unsafe usage
          if id.attempt != 0 {
            panic!("attempt wasn't 0");
          }
          let nonces = crate::tributary::dkg_confirmation_nonces(&key, &spec);
          Some(Transaction::DkgShares {
            attempt: id.attempt,
            sender_i: my_i,
            shares,
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

          // Tell the Tributary the key pair, get back the share for the MuSig signature
          let mut txn = db.txn();
          let share = crate::tributary::generated_key_pair::<D>(
            &mut txn,
            &key,
            &spec,
            &(Public(substrate_key), network_key.try_into().unwrap()),
          );
          txn.commit();

          match share {
            Ok(share) => {
              Some(Transaction::DkgConfirmed(id.attempt, share, Transaction::empty_signed()))
            }
            Err(p) => todo!("participant {p:?} sent invalid DKG confirmation preprocesses"),
          }
        }
      },
      ProcessorMessage::Sign(msg) => match msg {
        sign::ProcessorMessage::Preprocess { id, preprocess } => {
          if id.attempt == 0 {
            let mut txn = db.txn();
            MainDb::<D>::save_first_preprocess(&mut txn, id.id, preprocess);
            txn.commit();

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
          Some(Transaction::SignCompleted(id, tx, Transaction::empty_signed()))
        }
      },
      ProcessorMessage::Coordinator(inner_msg) => match inner_msg {
        coordinator::ProcessorMessage::SubstrateBlockAck { network, block, plans } => {
          assert_eq!(
            network, msg.network,
            "processor claimed to be a different network than it was for SubstrateBlockAck",
          );

          // Safe to use its own txn since this is static and just needs to be written before we
          // provide SubstrateBlock
          let mut txn = db.txn();
          TributaryDb::<D>::set_plan_ids(&mut txn, genesis, block, &plans);
          txn.commit();

          Some(Transaction::SubstrateBlock(block))
        }
        coordinator::ProcessorMessage::BatchPreprocess { id, block, preprocess } => {
          log::info!(
            "informed of batch (sign ID {}, attempt {}) for block {}",
            hex::encode(id.id),
            id.attempt,
            hex::encode(block),
          );
          // If this is the first attempt instance, synchronize around the block first
          if id.attempt == 0 {
            // Save the preprocess to disk so we can publish it later
            // This is fine to use its own TX since it's static and just needs to be written
            // before this message finishes it handling (or with this message's finished handling)
            let mut txn = db.txn();
            MainDb::<D>::save_first_preprocess(&mut txn, id.id, preprocess);
            MainDb::<D>::add_batch_to_block(&mut txn, msg.network, block, id.id);
            txn.commit();

            // TODO: This will publish one ExternalBlock per Batch. We should only publish one per
            // all batches within a block
            Some(Transaction::ExternalBlock(block.0))
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
          // TODO: Check this key's key pair's substrate key is authorized to publish batches
          // TODO: Check the batch ID is an atomic increment

          let tx = Serai::execute_batch(batch.clone());
          loop {
            match serai.publish(&tx).await {
              Ok(_) => {
                log::info!(
                  "executed batch {:?} {} (block {})",
                  batch.batch.network,
                  batch.batch.id,
                  hex::encode(batch.batch.block),
                );
                break;
              }
              Err(e) => {
                if let Ok(latest_block) = serai.get_latest_block().await {
                  if let Ok(Some(last)) =
                    serai.get_last_batch_for_network(latest_block.hash(), batch.batch.network).await
                  {
                    if last >= batch.batch.id {
                      log::info!(
                        "another coordinator executed batch {:?} {} (block {})",
                        batch.batch.network,
                        batch.batch.id,
                        hex::encode(batch.batch.block),
                      );
                      break;
                    }
                  }
                }
                log::error!("couldn't connect to Serai node to publish batch TX: {:?}", e);
                tokio::time::sleep(Duration::from_secs(10)).await;
              }
            }
          }

          None
        }
      },
    };

    // If this created a transaction, publish it
    if let Some(mut tx) = tx {
      log::trace!("processor message effected transaction {}", hex::encode(tx.hash()));
      let tributaries = tributaries.read().await;
      log::trace!("read global tributaries");
      let Some(tributary) = tributaries.get(&genesis) else {
        // TODO: This can happen since Substrate tells the Processor to generate commitments
        // at the same time it tells the Tributary to be created
        // There's no guarantee the Tributary will have been created though
        panic!("processor is operating on tributary we don't have");
      };
      let tributary = tributary.tributary.read().await;
      log::trace!("read specific tributary");

      match tx.kind() {
        TransactionKind::Provided(_) => {
          log::trace!("providing transaction {}", hex::encode(tx.hash()));
          let res = tributary.provide_transaction(tx).await;
          if !(res.is_ok() || (res == Err(ProvidedError::AlreadyProvided))) {
            panic!("provided an invalid transaction: {res:?}");
          }
        }
        TransactionKind::Signed(_) => {
          // Get the next nonce
          // TODO: This should be deterministic, not just DB-backed, to allow rebuilding validators
          // without the prior instance's DB
          // let mut txn = db.txn();
          // let nonce = MainDb::tx_nonce(&mut txn, msg.id, tributary);

          // TODO: This isn't deterministic, or at least DB-backed, and accordingly is unsafe
          log::trace!("getting next nonce for Tributary TX in response to processor message");
          let nonce = tributary
            .next_nonce(Ristretto::generator() * key.deref())
            .await
            .expect("publishing a TX to a tributary we aren't in");
          tx.sign(&mut OsRng, genesis, &key, nonce);

          publish_transaction(&tributary, tx).await;

          // txn.commit();
        }
        _ => panic!("created an unexpected transaction"),
      }
    }

    processors.ack(msg).await;
  }
}

pub async fn run<D: Db, Pro: Processors, P: P2p>(
  mut raw_db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  p2p: P,
  processors: Pro,
  serai: Serai,
) {
  let serai = Arc::new(serai);

  // Handle new Substrate blocks
  tokio::spawn(scan_substrate(raw_db.clone(), key.clone(), processors.clone(), serai.clone()));

  // Handle the Tributaries

  // Arc so this can be shared between the Tributary scanner task and the P2P task
  // Write locks on this may take a while to acquire
  let tributaries = Arc::new(RwLock::new(HashMap::<[u8; 32], ActiveTributary<D, P>>::new()));

  // Reload active tributaries from the database
  for spec in MainDb::new(&mut raw_db).active_tributaries().1 {
    let _ = add_tributary(
      raw_db.clone(),
      key.clone(),
      p2p.clone(),
      &mut *tributaries.write().await,
      spec,
    )
    .await;
  }

  // When we reach synchrony on an event requiring signing, send our preprocess for it
  let recognized_id = {
    let raw_db = raw_db.clone();
    let key = key.clone();
    let tributaries = tributaries.clone();
    move |network, genesis, id_type, id| {
      let raw_db = raw_db.clone();
      let key = key.clone();
      let tributaries = tributaries.clone();
      async move {
        // SubstrateBlockAck is fired before Preprocess, creating a race between Tributary ack
        // of the SubstrateBlock and the sending of all Preprocesses
        // A similar race condition exists when multiple Batches are present in a block
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

        let (ids, txs) = match id_type {
          RecognizedIdType::Block => {
            let block = id;

            let ids = MainDb::<D>::batches_in_block(&raw_db, network, block);
            let mut txs = vec![];
            for id in &ids {
              txs.push(Transaction::BatchPreprocess(SignData {
                plan: *id,
                attempt: 0,
                data: get_preprocess(&raw_db, *id).await,
                signed: Transaction::empty_signed(),
              }));
            }
            (ids, txs)
          }

          RecognizedIdType::Plan => (
            vec![id],
            vec![Transaction::SignPreprocess(SignData {
              plan: id,
              attempt: 0,
              data: get_preprocess(&raw_db, id).await,
              signed: Transaction::empty_signed(),
            })],
          ),
        };

        let tributaries = tributaries.read().await;
        let Some(tributary) = tributaries.get(&genesis) else {
          panic!("tributary we don't have came to consensus on an ExternalBlock");
        };
        let tributary = tributary.tributary.read().await;

        for mut tx in txs {
          // TODO: Same note as prior nonce acquisition
          log::trace!("getting next nonce for Tributary TX containing Batch signing data");
          let nonce = tributary
            .next_nonce(Ristretto::generator() * key.deref())
            .await
            .expect("publishing a TX to a tributary we aren't in");
          tx.sign(&mut OsRng, genesis, &key, nonce);

          publish_transaction(&tributary, tx).await;
        }

        ids
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
      tributaries.clone(),
    ));
  }

  // Spawn the heartbeat task, which will trigger syncing if there hasn't been a Tributary block
  // in a while (presumably because we're behind)
  tokio::spawn(heartbeat_tributaries(p2p.clone(), tributaries.clone()));

  // Handle P2P messages
  tokio::spawn(handle_p2p(Ristretto::generator() * key.deref(), p2p, tributaries.clone()));

  // Handle all messages from processors
  handle_processors(raw_db, key, serai, processors, tributaries).await;
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
