use core::time::Duration;
use std::collections::HashMap;

use async_trait::async_trait;

use tokio::{sync::mpsc, time::timeout};

use group::GroupEncoding;
use frost::curve::Ciphersuite;

use crate::coin::{Block, Coin};

/// A block number from the Substrate chain, considered a canonical orderer by all instances.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct CanonicalNumber(pub u64);

// TODO: Either move everything over or get rid of this
/// A block number of some arbitrary chain, later-affirmed by the Substrate chain.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct ChainNumber(pub u64);

/// Orders for the scanner.
#[derive(Clone, Debug)]
pub enum ScannerOrder<C: Ciphersuite> {
  /// Rotate the key being scanned for.
  /// If no key has been prior set, this will become the key with no further actions.
  /// If a key has been prior set, both keys will be scanned for as detailed in the Multisig
  /// documentation. The old key will eventually stop being scanned for, leaving just the
  /// updated-to key.
  RotateKey { activation_number: ChainNumber, key: C::G },
  /// Acknowledge having handled a block for a key
  AckBlock(C::G, ChainNumber),
}

#[derive(Clone, Debug)]
pub enum ScannerEvent<C: Coin> {
  // Block acknowledged. This number should be used for the Updates provided to Substrate
  Block(ChainNumber, <C::Block as Block>::Id),
  // Outputs received
  Outputs(<C::Curve as Ciphersuite>::G, <C::Block as Block>::Id, Vec<C::Output>),
}

pub type ScannerOrderChannel<C> = mpsc::UnboundedSender<ScannerOrder<C>>;
pub type ScannerEventChannel<C> = mpsc::UnboundedReceiver<ScannerEvent<C>>;

#[async_trait]
pub trait ScannerDb<C: Coin>: Send + Sync {
  async fn get_latest_scanned_block(&self, key: <C::Curve as Ciphersuite>::G) -> ChainNumber;
  async fn save_scanned_block(&mut self, key: <C::Curve as Ciphersuite>::G, block: ChainNumber);

  async fn get_block(&self, number: ChainNumber) -> Option<<C::Block as Block>::Id>;
  async fn save_block(&mut self, number: ChainNumber, id: <C::Block as Block>::Id);
}

#[derive(Debug)]
pub struct Scanner<C: Coin, D: ScannerDb<C>> {
  coin: C,
  db: D,
  keys: Vec<<C::Curve as Ciphersuite>::G>,

  orders: mpsc::UnboundedReceiver<ScannerOrder<C::Curve>>,
  events: mpsc::UnboundedSender<ScannerEvent<C>>,
}

#[derive(Debug)]
pub struct ScannerHandle<C: Coin> {
  pub orders: ScannerOrderChannel<C::Curve>,
  pub events: ScannerEventChannel<C>,
}

impl<C: Coin + 'static, D: ScannerDb<C> + 'static> Scanner<C, D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(coin: C, db: D) -> ScannerHandle<C> {
    let (orders_send, orders_recv) = mpsc::unbounded_channel();
    let (events_send, events_recv) = mpsc::unbounded_channel();
    tokio::spawn(
      Scanner { coin, db, keys: vec![], orders: orders_recv, events: events_send }.run(),
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
          Ok(latest) => latest,
          Err(_) => {
            log::warn!("Couldn't get {}'s latest block number", C::ID);
            break;
          }
        };

        for key in self.keys.clone() {
          let key_vec = key.to_bytes().as_ref().to_vec();
          let latest_scanned = {
            // Grab the latest scanned block according to the DB
            let db_scanned =
              usize::try_from(self.db.get_latest_scanned_block(key).await.0).unwrap();
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

            let i = ChainNumber(i.try_into().unwrap());
            let first = if let Some(id) = self.db.get_block(i).await {
              if id != block.id() {
                panic!("{} reorg'd from {id:?} to {:?}", C::ID, block.id());
              }
              false
            } else {
              self.db.save_block(i, block.id()).await;
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
              self.events.send(ScannerEvent::Block(i, block.id())).unwrap();
            }

            // Send all outputs
            self.events.send(ScannerEvent::Outputs(key, block.id(), outputs)).unwrap();
            // Write this number as scanned so we won't re-fire these outputs
            ram_scanned.insert(key_vec.clone(), i.0.try_into().unwrap());
          }
        }
      }

      // Handle any new orders
      if let Ok(order) = timeout(Duration::from_secs(1), self.orders.recv()).await {
        let order = order.expect("Scanner handler was dropped. Shutting down?");
        match order {
          ScannerOrder::RotateKey { key, .. } => {
            self.keys.push(key);
          }
          ScannerOrder::AckBlock(key, i) => self.db.save_scanned_block(key, i).await,
        }
      }
    }
  }
}
