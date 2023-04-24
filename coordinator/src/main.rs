#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(unreachable_code)]
#![allow(clippy::diverging_sub_expression)]

use std::{
  sync::Arc,
  time::{SystemTime, Duration},
  collections::{VecDeque, HashMap},
};

use zeroize::Zeroizing;

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use serai_db::{Db, MemDb};
use serai_client::Serai;

use tokio::{sync::RwLock, time::sleep};

use ::tributary::Tributary;

mod tributary;
use crate::tributary::{TributarySpec, Transaction};

mod db;
use db::MainDb;

mod p2p;
pub use p2p::*;

pub mod processor;
use processor::Processor;

mod substrate;

#[cfg(test)]
pub mod tests;

// This is a static to satisfy lifetime expectations
lazy_static::lazy_static! {
  static ref NEW_TRIBUTARIES: RwLock<VecDeque<TributarySpec>> = RwLock::new(VecDeque::new());
}

// Specifies a new tributary
async fn create_new_tributary<D: Db>(db: D, spec: TributarySpec) {
  // Save it to the database
  MainDb(db).add_active_tributary(&spec);
  // Add it to the queue
  // If we reboot before this is read from the queue, the fact it was saved to the database
  // means it'll be handled on reboot
  NEW_TRIBUTARIES.write().await.push_back(spec);
}

pub struct ActiveTributary<D: Db, P: P2p> {
  spec: TributarySpec,
  tributary: Arc<RwLock<Tributary<D, Transaction, P>>>,
}

// Adds a tributary into the specified HahMap
async fn add_tributary<D: Db, P: P2p>(
  db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  p2p: P,
  tributaries: &mut HashMap<[u8; 32], ActiveTributary<D, P>>,
  spec: TributarySpec,
) {
  let tributary = Tributary::<_, Transaction, _>::new(
    // TODO: Use a db on a distinct volume
    db,
    spec.genesis(),
    spec.start_time(),
    key,
    spec.validators(),
    p2p,
  )
  .await
  .unwrap();

  tributaries.insert(
    tributary.genesis(),
    ActiveTributary { spec, tributary: Arc::new(RwLock::new(tributary)) },
  );
}

pub async fn scan_substrate<D: Db, Pro: Processor>(
  db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  mut processor: Pro,
  serai: Serai,
) {
  let mut db = substrate::SubstrateDb::new(db);
  let mut last_substrate_block = db.last_block();

  loop {
    match substrate::handle_new_blocks(
      &mut db,
      &key,
      create_new_tributary,
      &mut processor,
      &serai,
      &mut last_substrate_block,
    )
    .await
    {
      // TODO: Should this use a notification system for new blocks?
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
pub async fn scan_tributaries<D: Db, Pro: Processor, P: P2p>(
  raw_db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  p2p: P,
  mut processor: Pro,
  tributaries: Arc<RwLock<HashMap<[u8; 32], ActiveTributary<D, P>>>>,
) {
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
        add_tributary(
          raw_db.clone(),
          key.clone(),
          p2p.clone(),
          // This is a short-lived write acquisition, which is why it should be fine
          &mut *tributaries.write().await,
          spec,
        )
        .await;
      }
    }

    // TODO: Instead of holding this lock long term, should this take in Arc RwLock and
    // re-acquire read locks?
    for ActiveTributary { spec, tributary } in tributaries.read().await.values() {
      tributary::scanner::handle_new_blocks::<_, _, P>(
        &mut tributary_db,
        &key,
        &mut processor,
        spec,
        &*tributary.read().await,
      )
      .await;
    }

    // Sleep for half the block time
    // TODO: Should we define a notification system for when a new block occurs?
    sleep(Duration::from_secs((Tributary::<D, Transaction, P>::block_time() / 2).into())).await;
  }
}

#[allow(clippy::type_complexity)]
pub async fn heartbeat_tributaries<D: Db, P: P2p>(
  p2p: P,
  tributaries: Arc<RwLock<HashMap<[u8; 32], ActiveTributary<D, P>>>>,
) {
  let ten_blocks_of_time =
    Duration::from_secs((Tributary::<D, Transaction, P>::block_time() * 10).into());

  loop {
    for ActiveTributary { spec: _, tributary } in tributaries.read().await.values() {
      let tributary = tributary.read().await;
      let tip = tributary.tip().await;
      let block_time =
        SystemTime::UNIX_EPOCH + Duration::from_secs(tributary.time_of_block(&tip).unwrap_or(0));

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
  p2p: P,
  tributaries: Arc<RwLock<HashMap<[u8; 32], ActiveTributary<D, P>>>>,
) {
  loop {
    let msg = p2p.receive().await;
    match msg.kind {
      P2pMessageKind::Tributary(genesis) => {
        let tributaries_read = tributaries.read().await;
        let Some(tributary) = tributaries_read.get(&genesis) else {
        log::debug!("received p2p message for unknown network");
        continue;
      };

        // This is misleading being read, as it will mutate the Tributary, yet there's
        // greater efficiency when it is read
        // The safety of it is also justified by Tributary::handle_message's documentation
        if tributary.tributary.read().await.handle_message(&msg.msg).await {
          P2p::broadcast(&p2p, msg.kind, msg.msg).await;
        }
      }

      // TODO: Respond with the missing block, if there are any
      P2pMessageKind::Heartbeat(genesis) => todo!(),
    }
  }
}

pub async fn run<D: Db, Pro: Processor, P: P2p>(
  raw_db: D,
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  p2p: P,
  processor: Pro,
  serai: Serai,
) {
  // Handle new Substrate blocks
  tokio::spawn(scan_substrate(raw_db.clone(), key.clone(), processor.clone(), serai.clone()));

  // Handle the Tributaries

  // Arc so this can be shared between the Tributary scanner task and the P2P task
  // Write locks on this may take a while to acquire
  let tributaries = Arc::new(RwLock::new(HashMap::<[u8; 32], ActiveTributary<D, P>>::new()));

  // Reload active tributaries from the database
  // TODO: Can MainDb take a borrow?
  for spec in MainDb(raw_db.clone()).active_tributaries().1 {
    add_tributary(raw_db.clone(), key.clone(), p2p.clone(), &mut *tributaries.write().await, spec)
      .await;
  }

  // Handle new blocks for each Tributary
  tokio::spawn(scan_tributaries(
    raw_db.clone(),
    key.clone(),
    p2p.clone(),
    processor,
    tributaries.clone(),
  ));

  // Spawn the heartbeat task, which will trigger syncing if there hasn't been a Tributary block
  // in a while (presumably because we're behind)
  tokio::spawn(heartbeat_tributaries(p2p.clone(), tributaries.clone()));

  // Handle P2P messages
  // TODO: We also have to broadcast blocks once they're added
  tokio::spawn(handle_p2p(p2p, tributaries));

  loop {
    // Handle all messages from processors
    todo!()
  }
}

#[tokio::main]
async fn main() {
  let db = MemDb::new(); // TODO

  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::ZERO); // TODO
  let p2p = LocalP2p::new(1).swap_remove(0); // TODO

  let processor = processor::MemProcessor::new(); // TODO

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
  run(db, key, p2p, processor, serai().await).await
}
