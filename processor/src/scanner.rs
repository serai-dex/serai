use core::{marker::PhantomData, time::Duration};
use std::collections::HashMap;

use tokio::{sync::mpsc, time::timeout};

use group::GroupEncoding;
use frost::curve::Ciphersuite;

use crate::{
  Db,
  coin::{Block, Coin},
};

const CHANNEL_EXPECT: &str = "Scanner handler was dropped. Shutting down?";

/// Orders for the scanner.
#[derive(Clone, Debug)]
pub enum ScannerOrder<C: Ciphersuite> {
  /// Rotate the key being scanned for.
  /// If no key has been prior set, this will become the key with no further actions.
  /// If a key has been prior set, both keys will be scanned for as detailed in the Multisig
  /// documentation. The old key will eventually stop being scanned for, leaving just the
  /// updated-to key.
  RotateKey { activation_number: usize, key: C::G },
  /// Acknowledge having handled a block for a key
  AckBlock(C::G, usize),
}

#[derive(Clone, Debug)]
pub enum ScannerEvent<C: Coin> {
  // Block acknowledged. This number should be used for the Updates provided to Substrate
  Block(usize, <C::Block as Block>::Id),
  // Outputs received
  Outputs(<C::Curve as Ciphersuite>::G, <C::Block as Block>::Id, Vec<C::Output>),
}

pub type ScannerOrderChannel<C> = mpsc::UnboundedSender<ScannerOrder<C>>;
pub type ScannerEventChannel<C> = mpsc::UnboundedReceiver<ScannerEvent<C>>;

#[derive(Debug)]
struct ScannerDb<C: Coin, D: Db>(D, PhantomData<C>);
impl<C: Coin, D: Db> ScannerDb<C, D> {
  fn scanner_key(dst: &'static [u8], key: &[u8]) -> Vec<u8> {
    [b"SCANNER", dst, key].concat().to_vec()
  }

  fn scanned_block_key(key: <C::Curve as Ciphersuite>::G) -> Vec<u8> {
    Self::scanner_key(b"scanned_block", key.to_bytes().as_ref())
  }
  fn save_scanned_block(&mut self, key: <C::Curve as Ciphersuite>::G, block: usize) {
    self.0.put(Self::scanned_block_key(key), u64::try_from(block).unwrap().to_le_bytes())
  }
  fn latest_scanned_block(&self, key: <C::Curve as Ciphersuite>::G) -> usize {
    let bytes = self.0.get(Self::scanned_block_key(key)).unwrap_or(vec![0; 8]);
    u64::from_le_bytes(bytes.try_into().unwrap()).try_into().unwrap()
  }

  fn block_key(number: usize) -> Vec<u8> {
    Self::scanner_key(b"block", u64::try_from(number).unwrap().to_le_bytes().as_ref())
  }
  fn save_block(&mut self, number: usize, id: <C::Block as Block>::Id) {
    self.0.put(Self::block_key(number), id)
  }
  fn block(&self, number: usize) -> Option<<C::Block as Block>::Id> {
    self.0.get(Self::block_key(number)).map(|id| {
      let mut res = <C::Block as Block>::Id::default();
      res.as_mut().copy_from_slice(&id);
      res
    })
  }
}

#[derive(Debug)]
pub struct Scanner<C: Coin, D: Db> {
  coin: C,
  db: ScannerDb<C, D>,
  keys: Vec<<C::Curve as Ciphersuite>::G>,

  orders: mpsc::UnboundedReceiver<ScannerOrder<C::Curve>>,
  events: mpsc::UnboundedSender<ScannerEvent<C>>,
}

#[derive(Debug)]
pub struct ScannerHandle<C: Coin> {
  pub orders: ScannerOrderChannel<C::Curve>,
  pub events: ScannerEventChannel<C>,
}

impl<C: Coin + 'static, D: Db + 'static> Scanner<C, D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(coin: C, db: D) -> ScannerHandle<C> {
    let (orders_send, orders_recv) = mpsc::unbounded_channel();
    let (events_send, events_recv) = mpsc::unbounded_channel();
    tokio::spawn(
      Scanner {
        coin,
        db: ScannerDb(db, PhantomData),
        keys: vec![],
        orders: orders_recv,
        events: events_send,
      }
      .run(),
    );
    ScannerHandle { orders: orders_send, events: events_recv }
  }

  // An async function, to be spawned on a task, to discover and report outputs
  async fn run(mut self) {
    let mut ram_scanned = HashMap::new();

    loop {
      // Scan new blocks
      {
        let latest = match self.coin.get_latest_block_number().await {
          // Only scan confirmed blocks, which we consider effectively finalized
          // CONFIRMATIONS - 1 as whatever's in the latest block already has 1 confirm
          Ok(latest) => latest.saturating_sub(C::CONFIRMATIONS.saturating_sub(1)),
          Err(_) => {
            log::warn!("Couldn't get {}'s latest block number", C::ID);
            break;
          }
        };

        for key in self.keys.clone() {
          let key_vec = key.to_bytes().as_ref().to_vec();
          let latest_scanned = {
            // Grab the latest scanned block according to the DB
            let db_scanned = self.db.latest_scanned_block(key);
            // We may, within this process's lifetime, have scanned more blocks
            // If they're still being processed, we will not have officially written them to the DB
            // as scanned yet
            // That way, if the process terminates, and is rebooted, we'll rescan from a handled
            // point, re-firing all events along the way, enabling them to be properly processed
            // In order to not re-fire them within this process's lifetime, check our RAM cache
            // of what we've scanned
            let ram_scanned = ram_scanned.get(&key_vec).cloned().unwrap_or(0);
            // Pick whichever is higher
            db_scanned.max(ram_scanned)
          };

          for i in (latest_scanned + 1) ..= latest {
            // TODO: Check for key deprecation

            let block = match self.coin.get_block(i).await {
              Ok(block) => block,
              Err(_) => {
                log::warn!("Couldn't get {} block {i:?}", C::ID);
                break;
              }
            };

            let first = if let Some(id) = self.db.block(i) {
              // TODO: Also check this block builds off the previous block
              if id != block.id() {
                panic!("{} reorg'd from {id:?} to {:?}", C::ID, block.id());
              }
              false
            } else {
              self.db.save_block(i, block.id());
              true
            };

            let outputs = match self.coin.get_outputs(&block, key).await {
              Ok(outputs) => outputs,
              Err(_) => {
                log::warn!("Couldn't scan {} block {i:?}", C::ID);
                break;
              }
            };

            // Filter out outputs with IDs we've already handled
            // TODO (here? at site of event recipience?)
            /*
            let outputs = outputs.drain(..).filter(|output| {
              let id = output.id().as_ref().to_vec();
              db.has_output(id) || ram.has_output(id)
            }).collect::<Vec<_>>();
            */

            // TODO: Still fire an empty Outputs event if we haven't had inputs in a while
            if outputs.is_empty() {
              continue;
            }

            // Fire the block event
            // This is intended for group acknowledgement of what block we're on, not only
            // providing a heartbeat, yet also letting coins like Monero schedule themselves
            if first {
              self.events.send(ScannerEvent::Block(i, block.id())).expect(CHANNEL_EXPECT);
            }

            // Send all outputs
            self
              .events
              .send(ScannerEvent::Outputs(key, block.id(), outputs))
              .expect(CHANNEL_EXPECT);
            // Write this number as scanned so we won't re-fire these outputs
            ram_scanned.insert(key_vec.clone(), i);
          }
        }
      }

      // Handle any new orders
      if let Ok(order) = timeout(Duration::from_secs(1), self.orders.recv()).await {
        match order.expect(CHANNEL_EXPECT) {
          ScannerOrder::RotateKey { key, .. } => {
            self.keys.push(key);
          }
          ScannerOrder::AckBlock(key, i) => self.db.save_scanned_block(key, i),
        }
      }
    }
  }
}
