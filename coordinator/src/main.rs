#![allow(dead_code)]
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

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use serai_db::{Db, MemDb};
use serai_client::Serai;

use tokio::{sync::RwLock, time::sleep};

use ::tributary::{ReadWrite, Block, Tributary};

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
  pub spec: TributarySpec,
  pub tributary: Arc<RwLock<Tributary<D, Transaction, P>>>,
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

    // TODO: Make a TributaryReader which only requires a DB handle and safely doesn't require
    // locks
    // Use that here
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
    Duration::from_secs((10 * Tributary::<D, Transaction, P>::block_time()).into());

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
  our_key: <Ristretto as Ciphersuite>::G,
  p2p: P,
  tributaries: Arc<RwLock<HashMap<[u8; 32], ActiveTributary<D, P>>>>,
) {
  loop {
    let mut msg = p2p.receive().await;
    match msg.kind {
      P2pMessageKind::Tributary(genesis) => {
        let tributaries_read = tributaries.read().await;
        let Some(tributary) = tributaries_read.get(&genesis) else {
          log::debug!("received p2p message for unknown network");
          continue;
        };

        if tributary.tributary.write().await.handle_message(&msg.msg).await {
          P2p::broadcast(&p2p, msg.kind, msg.msg).await;
        }
      }

      // TODO: Rate limit this
      P2pMessageKind::Heartbeat(genesis) => {
        let tributaries_read = tributaries.read().await;
        let Some(tributary) = tributaries_read.get(&genesis) else {
          log::debug!("received heartbeat message for unknown network");
          continue;
        };

        if msg.msg.len() != 32 {
          log::error!("validator sent invalid heartbeat");
          continue;
        }

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

        let mut latest = msg.msg.try_into().unwrap();
        // TODO: All of these calls don't *actually* need a read lock, just access to a DB handle
        // We can reduce lock contention accordingly
        while let Some(next) = tributary_read.block_after(&latest) {
          let mut res = tributary_read.block(&next).unwrap().serialize();
          res.extend(tributary_read.commit(&next).unwrap());
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

        let tributaries = tributaries.read().await;
        let Some(tributary) = tributaries.get(&genesis) else {
          log::debug!("received block message for unknown network");
          continue;
        };

        // TODO: We take a notable amount of time to add blocks when we're missing provided
        // transactions
        // Any tributary with missing provided transactions will cause this P2P loop to halt
        // Make a separate queue for this
        let res = tributary.tributary.write().await.sync_block(block, msg.msg).await;
        log::debug!("received block from {:?}, sync_block returned {}", msg.sender, res);
      }
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
  tokio::spawn(handle_p2p(Ristretto::generator() * key.deref(), p2p, tributaries));

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
