#![allow(unused_variables)]
#![allow(unreachable_code)]
#![allow(clippy::diverging_sub_expression)]

use core::ops::Deref;
use std::{
  sync::Arc,
  time::{SystemTime, Duration},
  collections::{VecDeque, HashMap},
};

use zeroize::Zeroizing;
use rand_core::OsRng;

use blake2::Digest;

use ciphersuite::{
  group::{
    ff::{Field, PrimeField},
    GroupEncoding,
  },
  Ciphersuite, Ristretto,
};

use serai_db::{DbTxn, Db, MemDb};

use serai_client::{
  subxt::{config::extrinsic_params::BaseExtrinsicParamsBuilder, tx::Signer},
  Public, PairSigner, Serai,
};

use tokio::{
  sync::{
    mpsc::{self, UnboundedSender},
    RwLock,
  },
  time::sleep,
};

use ::tributary::{
  ReadWrite, ProvidedError, TransactionKind, Transaction as TransactionTrait, Block, Tributary,
  TributaryReader,
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

// This is a static to satisfy lifetime expectations
lazy_static::lazy_static! {
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
  serai: Serai,
) {
  let mut db = substrate::SubstrateDb::new(db);
  let mut last_substrate_block = db.last_block();

  loop {
    match substrate::handle_new_blocks(
      &mut db,
      &key,
      |db: &mut D, spec: TributarySpec| {
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
      &mut last_substrate_block,
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
pub async fn scan_tributaries<D: Db, Pro: Processors, P: P2p>(
  raw_db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  recognized_id_send: UnboundedSender<([u8; 32], RecognizedIdType, [u8; 32])>,
  p2p: P,
  processors: Pro,
  tributaries: Arc<RwLock<Tributaries<D, P>>>,
) {
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
      tributary::scanner::handle_new_blocks::<_, _>(
        &mut tributary_db,
        &key,
        &recognized_id_send,
        &processors,
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

#[allow(clippy::type_complexity)]
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
        P2p::broadcast(&p2p, P2pMessageKind::Heartbeat(tributary.genesis()), tip.to_vec()).await;
      }
    }

    // Only check once every 10 blocks of time
    sleep(ten_blocks_of_time).await;
  }
}

#[allow(clippy::type_complexity)]
pub async fn handle_p2p<D: Db, P: P2p>(
  our_key: <Ristretto as Ciphersuite>::G,
  p2p: P,
  tributaries: Arc<RwLock<Tributaries<D, P>>>,
) {
  loop {
    let mut msg = p2p.receive().await;
    match msg.kind {
      P2pMessageKind::Tributary(genesis) => {
        let tributaries = tributaries.read().await;
        let Some(tributary) = tributaries.get(&genesis) else {
          log::debug!("received p2p message for unknown network");
          continue;
        };

        if tributary.tributary.write().await.handle_message(&msg.msg).await {
          P2p::broadcast(&p2p, msg.kind, msg.msg).await;
        }
      }

      // TODO2: Rate limit this per validator
      P2pMessageKind::Heartbeat(genesis) => {
        if msg.msg.len() != 32 {
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
        // THis isn't a secure source of entropy, yet it's fine for this
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

        let mut latest = msg.msg.try_into().unwrap();
        while let Some(next) = reader.block_after(&latest) {
          let mut res = reader.block(&next).unwrap().serialize();
          res.extend(reader.commit(&next).unwrap());
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
        // TODO
        tokio::spawn({
          let tributaries = tributaries.clone();
          async move {
            let tributaries = tributaries.read().await;
            let Some(tributary) = tributaries.get(&genesis) else {
              log::debug!("received block message for unknown network");
              return;
            };

            let res = tributary.tributary.write().await.sync_block(block, msg.msg).await;
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

#[allow(clippy::type_complexity)]
pub async fn handle_processors<D: Db, Pro: Processors, P: P2p>(
  mut db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  serai: Serai,
  mut processors: Pro,
  tributaries: Arc<RwLock<Tributaries<D, P>>>,
) {
  let pub_key = Ristretto::generator() * key.deref();

  // TODO: This is cursed. serai_client has to handle this for us
  let substrate_signer = {
    let mut bytes = Zeroizing::new([0; 96]);
    // Private key
    bytes[.. 32].copy_from_slice(&key.to_repr());
    // Nonce
    let nonce = Zeroizing::new(blake2::Blake2s256::digest(&bytes));
    bytes[32 .. 64].copy_from_slice(nonce.as_ref());
    // Public key
    bytes[64 ..].copy_from_slice(&pub_key.to_bytes());
    PairSigner::new(schnorrkel::keys::Keypair::from_bytes(bytes.as_ref()).unwrap().into())
  };

  loop {
    let msg = processors.recv().await;

    // TODO2: This is slow, and only works as long as a network only has a single Tributary
    // (which means there's a lack of multisig rotation)
    let genesis = {
      let mut genesis = None;
      for tributary in tributaries.read().await.values() {
        if tributary.spec.set().network == msg.network {
          genesis = Some(tributary.spec.genesis());
          break;
        }
      }
      genesis.unwrap()
    };

    let tx = match msg.msg {
      ProcessorMessage::KeyGen(inner_msg) => match inner_msg {
        key_gen::ProcessorMessage::Commitments { id, commitments } => {
          Some(Transaction::DkgCommitments(id.attempt, commitments, Transaction::empty_signed()))
        }
        key_gen::ProcessorMessage::Shares { id, shares } => {
          Some(Transaction::DkgShares(id.attempt, shares, Transaction::empty_signed()))
        }
        key_gen::ProcessorMessage::GeneratedKeyPair { id, substrate_key, coin_key } => {
          assert_eq!(
            id.set.network, msg.network,
            "processor claimed to be a different network than it was for SubstrateBlockAck",
          );
          // TODO: Also check the other KeyGenId fields

          // TODO: Is this safe?
          let Ok(nonce) = serai.get_nonce(&substrate_signer.address()).await else {
            log::error!("couldn't connect to Serai node to get nonce");
            todo!(); // TODO
          };

          let tx = serai
            .sign(
              &substrate_signer,
              &Serai::vote(
                msg.network,
                (
                  Public(substrate_key),
                  coin_key
                    .try_into()
                    .expect("external key from processor exceeded max external key length"),
                ),
              ),
              nonce,
              BaseExtrinsicParamsBuilder::new(),
            )
            .expect(
              "tried to sign an invalid payload despite creating the payload via serai_client",
            );

          match serai.publish(&tx).await {
            Ok(hash) => {
              log::info!("voted on key pair for {:?} in TX {}", id.set, hex::encode(hash))
            }
            Err(e) => {
              log::error!("couldn't connect to Serai node to publish TX: {:?}", e);
              todo!(); // TODO
            }
          }

          None
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
        // TODO
        sign::ProcessorMessage::Completed { .. } => todo!(),
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
        coordinator::ProcessorMessage::BatchPreprocess { id, preprocess } => {
          // If this is the first attempt instance, synchronize around the block first
          if id.attempt == 0 {
            // Save the preprocess to disk so we can publish it later
            // This is fine to use its own TX since it's static and just needs to be written
            // before this message finishes it handling (or with this message's finished handling)
            let mut txn = db.txn();
            MainDb::<D>::save_first_preprocess(&mut txn, id.id, preprocess);
            txn.commit();

            Some(Transaction::ExternalBlock(id.id))
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
      ProcessorMessage::Substrate(msg) => match msg {
        // TODO
        processor_messages::substrate::ProcessorMessage::Update { .. } => todo!(),
      },
    };

    // If this created a transaction, publish it
    if let Some(mut tx) = tx {
      let tributaries = tributaries.read().await;
      let Some(tributary) = tributaries.get(&genesis) else {
        // TODO: This can happen since Substrate tells the Processor to generate commitments
        // at the same time it tells the Tributary to be created
        // There's no guarantee the Tributary will have been created though
        panic!("processor is operating on tributary we don't have");
      };
      let tributary = tributary.tributary.read().await;

      match tx.kind() {
        TransactionKind::Provided(_) => {
          let res = tributary.provide_transaction(tx).await;
          if !(res.is_ok() || (res == Err(ProvidedError::AlreadyProvided))) {
            panic!("provided an invalid transaction: {res:?}");
          }
        }
        TransactionKind::Signed(_) => {
          // Get the next nonce
          // let mut txn = db.txn();
          // let nonce = MainDb::tx_nonce(&mut txn, msg.id, tributary);

          let nonce = 0; // TODO
          tx.sign(&mut OsRng, genesis, &key, nonce);

          publish_transaction(&tributary, tx).await;

          // txn.commit();
        }
        _ => panic!("created an unexpected transaction"),
      }
    }
  }
}

pub async fn run<D: Db, Pro: Processors, P: P2p>(
  mut raw_db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  p2p: P,
  processors: Pro,
  serai: Serai,
) {
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

  // Handle new blocks for each Tributary
  let (recognized_id_send, mut recognized_id_recv) = mpsc::unbounded_channel();
  {
    let raw_db = raw_db.clone();
    tokio::spawn(scan_tributaries(
      raw_db,
      key.clone(),
      recognized_id_send,
      p2p.clone(),
      processors.clone(),
      tributaries.clone(),
    ));
  }

  // When we reach consensus on a new external block, send our BatchPreprocess for it
  tokio::spawn({
    let raw_db = raw_db.clone();
    let key = key.clone();
    let tributaries = tributaries.clone();
    async move {
      loop {
        if let Some((genesis, id_type, id)) = recognized_id_recv.recv().await {
          let mut tx = match id_type {
            RecognizedIdType::Block => Transaction::BatchPreprocess(SignData {
              plan: id,
              attempt: 0,
              data: MainDb::<D>::first_preprocess(&raw_db, id),
              signed: Transaction::empty_signed(),
            }),

            RecognizedIdType::Plan => Transaction::SignPreprocess(SignData {
              plan: id,
              attempt: 0,
              data: MainDb::<D>::first_preprocess(&raw_db, id),
              signed: Transaction::empty_signed(),
            }),
          };

          let nonce = 0; // TODO
          tx.sign(&mut OsRng, genesis, &key, nonce);

          let tributaries = tributaries.read().await;
          let Some(tributary) = tributaries.get(&genesis) else {
            panic!("tributary we don't have came to consensus on an ExternalBlock");
          };
          let tributary = tributary.tributary.read().await;

          publish_transaction(&tributary, tx).await;
        } else {
          log::warn!("recognized_id_send was dropped. are we shutting down?");
          break;
        }
      }
    }
  });

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
  let db = MemDb::new(); // TODO

  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::ZERO); // TODO
  let p2p = LocalP2p::new(1).swap_remove(0); // TODO

  let processors = processors::MemProcessors::new(); // TODO

  let serai = || async {
    loop {
      let Ok(serai) = Serai::new("ws://127.0.0.1:9944").await else {
        log::error!("couldn't connect to the Serai node");
        sleep(Duration::from_secs(5)).await;
        continue
      };
      return serai;
    }
  };
  run(db, key, p2p, processors, serai().await).await
}
