use core::{marker::PhantomData, time::Duration};
use std::collections::{HashSet, HashMap};

use group::GroupEncoding;
use frost::curve::Ciphersuite;

use log::{info, debug, warn};
use tokio::{sync::mpsc, time::timeout};

use crate::{
  Db,
  coin::{Output, Block, Coin},
};

/// Orders for the scanner.
#[derive(Clone, Debug)]
pub enum ScannerOrder<C: Coin> {
  /// Rotate the key being scanned for.
  /// If no key has been prior set, this will become the key with no further actions.
  /// If a key has been prior set, both keys will be scanned for as detailed in the Multisig
  /// documentation. The old key will eventually stop being scanned for, leaving just the
  /// updated-to key.
  RotateKey { activation_number: usize, key: <C::Curve as Ciphersuite>::G },
  /// Acknowledge having handled a block for a key
  AckBlock(<C::Curve as Ciphersuite>::G, <C::Block as Block<C>>::Id),
}

#[derive(Clone, Debug)]
pub enum ScannerEvent<C: Coin> {
  // Outputs received
  Outputs(<C::Curve as Ciphersuite>::G, <C::Block as Block<C>>::Id, Vec<C::Output>),
}

pub type ScannerOrderChannel<C> = mpsc::UnboundedSender<ScannerOrder<C>>;
pub type ScannerEventChannel<C> = mpsc::UnboundedReceiver<ScannerEvent<C>>;

#[derive(Clone, Debug)]
struct ScannerDb<C: Coin, D: Db>(D, PhantomData<C>);
impl<C: Coin, D: Db> ScannerDb<C, D> {
  fn scanner_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    [b"SCANNER", dst, key.as_ref()].concat().to_vec()
  }

  fn block_key(number: usize) -> Vec<u8> {
    Self::scanner_key(b"block_id", u64::try_from(number).unwrap().to_le_bytes())
  }
  fn block_number_key(id: &<C::Block as Block<C>>::Id) -> Vec<u8> {
    Self::scanner_key(b"block_number", id)
  }
  fn save_block(&mut self, number: usize, id: &<C::Block as Block<C>>::Id) {
    // TODO: Use a TX here
    self.0.put(Self::scanner_key(b"corrupt", b""), b"");
    self.0.put(Self::block_number_key(id), u64::try_from(number).unwrap().to_le_bytes());
    self.0.put(Self::block_key(number), id);
    self.0.del(Self::scanner_key(b"corrupt", b""));
  }
  fn block(&self, number: usize) -> Option<<C::Block as Block<C>>::Id> {
    self.0.get(Self::block_key(number)).map(|id| {
      let mut res = <C::Block as Block<C>>::Id::default();
      res.as_mut().copy_from_slice(&id);
      res
    })
  }
  fn block_number(&self, id: &<C::Block as Block<C>>::Id) -> Option<usize> {
    self
      .0
      .get(Self::block_number_key(id))
      .map(|number| u64::from_le_bytes(number.try_into().unwrap()).try_into().unwrap())
  }

  fn active_keys_key() -> Vec<u8> {
    Self::scanner_key(b"active_keys", b"")
  }
  fn add_active_key(&mut self, key: <C::Curve as Ciphersuite>::G) {
    let mut keys = self.0.get(Self::active_keys_key()).unwrap_or(vec![]);
    keys.extend(key.to_bytes().as_ref());
    self.0.put(Self::active_keys_key(), keys);
  }
  fn active_keys(&self) -> Vec<<C::Curve as Ciphersuite>::G> {
    let bytes_vec = self.0.get(Self::active_keys_key()).unwrap_or(vec![]);
    let mut bytes: &[u8] = bytes_vec.as_ref();

    let mut res = Vec::with_capacity(bytes.len() / 32);
    while !bytes.is_empty() {
      res.push(C::Curve::read_G(&mut bytes).unwrap());
    }
    res
  }

  fn seen_key(id: &<C::Output as Output>::Id) -> Vec<u8> {
    Self::scanner_key(b"seen", id)
  }
  fn seen(&self, id: &<C::Output as Output>::Id) -> bool {
    self.0.get(Self::seen_key(id)).is_some()
  }

  fn outputs_key(
    key: &<C::Curve as Ciphersuite>::G,
    block: &<C::Block as Block<C>>::Id,
  ) -> Vec<u8> {
    let key_bytes = key.to_bytes();
    let key = key_bytes.as_ref();
    // This should be safe without the bincode serialize. Using bincode lets us not worry/have to
    // think about this
    let db_key = bincode::serialize(&(key, block.as_ref())).unwrap();
    // Assert this is actually length prefixing
    debug_assert!(db_key.len() >= (1 + key.len() + 1 + block.as_ref().len()));
    Self::scanner_key(b"outputs", db_key)
  }
  fn save_outputs(
    &mut self,
    key: &<C::Curve as Ciphersuite>::G,
    block: &<C::Block as Block<C>>::Id,
    outputs: &[C::Output],
  ) {
    let mut bytes = Vec::with_capacity(outputs.len() * 64);
    for output in outputs {
      output.write(&mut bytes).unwrap();
    }
    self.0.put(Self::outputs_key(key, block), bytes);
  }
  fn outputs(
    &self,
    key: &<C::Curve as Ciphersuite>::G,
    block: &<C::Block as Block<C>>::Id,
  ) -> Option<Vec<C::Output>> {
    let bytes_vec = self.0.get(Self::outputs_key(key, block))?;
    let mut bytes: &[u8] = bytes_vec.as_ref();

    let mut res = vec![];
    while !bytes.is_empty() {
      res.push(C::Output::read(&mut bytes).unwrap());
    }
    Some(res)
  }

  fn scanned_block_key(key: &<C::Curve as Ciphersuite>::G) -> Vec<u8> {
    Self::scanner_key(b"scanned_block", key.to_bytes())
  }
  fn save_scanned_block(
    &mut self,
    key: &<C::Curve as Ciphersuite>::G,
    block: usize,
  ) -> Vec<<C::Output as Output>::Id> {
    let new_key = self.0.get(Self::scanned_block_key(key)).is_none();
    let outputs = self.block(block).and_then(|id| self.outputs(key, &id));
    // Either this is a new key, with no outputs, or we're acknowledging this block
    // If we're acknowledging it, we should have outputs available
    assert_eq!(new_key, outputs.is_none());

    // TODO: Use a TX here
    self.0.put(Self::scanner_key(b"corrupt", b""), b"");

    // Mark all the outputs from this block as seen
    let mut ids = vec![];
    for output in outputs.unwrap_or(vec![]) {
      let id = output.id();
      self.0.put(Self::seen_key(&id), b"");
      ids.push(id);
    }

    self.0.put(Self::scanned_block_key(key), u64::try_from(block).unwrap().to_le_bytes());

    self.0.del(Self::scanner_key(b"corrupt", b""));

    // Return this block's outputs so they can be pruned from the RAM cache
    ids
  }
  fn latest_scanned_block(&self, key: <C::Curve as Ciphersuite>::G) -> usize {
    let bytes = self.0.get(Self::scanned_block_key(&key)).unwrap_or(vec![0; 8]);
    u64::from_le_bytes(bytes.try_into().unwrap()).try_into().unwrap()
  }
}

/// The Scanner emits events relating to the blockchain, notably received outputs.
/// It WILL NOT fail to emit an event, even if it reboots at selected moments.
/// It MAY fire the same event multiple times.
#[derive(Debug)]
pub struct Scanner<C: Coin, D: Db> {
  coin: C,
  db: ScannerDb<C, D>,
  keys: Vec<<C::Curve as Ciphersuite>::G>,

  orders: mpsc::UnboundedReceiver<ScannerOrder<C>>,
  events: mpsc::UnboundedSender<ScannerEvent<C>>,
}

#[derive(Debug)]
pub struct ScannerHandle<C: Coin, D: Db> {
  db: ScannerDb<C, D>,
  pub orders: ScannerOrderChannel<C>,
  pub events: ScannerEventChannel<C>,
}

impl<C: Coin, D: Db> ScannerHandle<C, D> {
  pub fn outputs(
    &self,
    key: &<C::Curve as Ciphersuite>::G,
    block: &<C::Block as Block<C>>::Id,
  ) -> Vec<C::Output> {
    let outputs = self.db.outputs(key, block);
    if let Some(outputs) = outputs {
      return outputs;
    }

    // TODO: Cleanly handle this
    if self.db.block_number(block).unwrap_or(usize::MAX) > self.db.latest_scanned_block(*key) {
      panic!("node behind");
    }

    outputs.expect("asked for outputs of a block without any")
  }
}

impl<C: Coin, D: Db> Scanner<C, D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(coin: C, db: D) -> (ScannerHandle<C, D>, Vec<<C::Curve as Ciphersuite>::G>) {
    if db.get(ScannerDb::<C, D>::scanner_key(b"corrupt", b"")).is_some() {
      panic!("scanner DB is corrupt");
    }

    let (orders_send, orders_recv) = mpsc::unbounded_channel();
    let (events_send, events_recv) = mpsc::unbounded_channel();
    let db = ScannerDb(db, PhantomData);
    let keys = db.active_keys();
    tokio::spawn(
      Scanner {
        coin,
        db: db.clone(),
        keys: keys.clone(),
        orders: orders_recv,
        events: events_send,
      }
      .run(),
    );
    (ScannerHandle { db, orders: orders_send, events: events_recv }, keys)
  }

  // An async function, to be spawned on a task, to discover and report outputs
  async fn run(mut self) {
    const CHANNEL_MSG: &str = "Scanner handler was dropped. Shutting down?";
    let handle_recv = |channel: Option<_>| {
      if channel.is_none() {
        info!("{}", CHANNEL_MSG);
      }
      channel
    };
    let handle_send = |channel: Result<_, _>| {
      if channel.is_err() {
        info!("{}", CHANNEL_MSG);
      }
      channel
    };

    let mut ram_scanned = HashMap::new();
    let mut ram_outputs = HashSet::new();

    loop {
      // Scan new blocks
      {
        let latest = match self.coin.get_latest_block_number().await {
          // Only scan confirmed blocks, which we consider effectively finalized
          // CONFIRMATIONS - 1 as whatever's in the latest block already has 1 confirm
          Ok(latest) => latest.saturating_sub(C::CONFIRMATIONS.saturating_sub(1)),
          Err(_) => {
            warn!("Couldn't get {}'s latest block number", C::ID);
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
            // We are allowed to re-fire them within this lifetime. It's just wasteful
            let ram_scanned = ram_scanned.get(&key_vec).cloned().unwrap_or(0);
            // Pick whichever is higher
            db_scanned.max(ram_scanned)
          };

          for i in (latest_scanned + 1) ..= latest {
            // TODO: Check for key deprecation

            let block = match self.coin.get_block(i).await {
              Ok(block) => block,
              Err(_) => {
                warn!("Couldn't get {} block {i}", C::ID);
                break;
              }
            };
            let block_id = block.id();

            if let Some(id) = self.db.block(i) {
              // TODO: Also check this block builds off the previous block
              if id != block.id() {
                panic!("{} reorg'd from {id:?} to {:?}", C::ID, hex::encode(block_id));
              }
            } else {
              info!("Found new block: {}", hex::encode(&block_id));
              self.db.save_block(i, &block_id);
            }

            let outputs = match self.coin.get_outputs(&block, key).await {
              Ok(outputs) => outputs,
              Err(_) => {
                warn!("Couldn't scan {} block {i:?}", C::ID);
                break;
              }
            };

            // Panic if we've already seen these outputs
            for output in &outputs {
              let id = output.id();
              // On Bitcoin, the output ID should be unique for a given chain
              // On Monero, it's trivial to make an output sharing an ID with another
              // We should only scan outputs with valid IDs however, which will be unique
              let seen = self.db.seen(&id);
              let id = id.as_ref().to_vec();
              if seen || ram_outputs.contains(&id) {
                panic!("scanned an output multiple times");
              }
              ram_outputs.insert(id);
            }

            // TODO: Still fire an empty Outputs event if we haven't had inputs in a while
            if outputs.is_empty() {
              continue;
            }

            // Save the outputs to disk
            self.db.save_outputs(&key, &block_id, &outputs);

            // Send all outputs
            if handle_send(self.events.send(ScannerEvent::Outputs(key, block_id, outputs))).is_err()
            {
              return;
            }
            // Write this number as scanned so we won't re-fire these outputs
            ram_scanned.insert(key_vec.clone(), i);
          }
        }
      }

      // Handle any new orders
      if let Ok(order) = timeout(Duration::from_secs(1), self.orders.recv()).await {
        match {
          match handle_recv(order) {
            None => return,
            Some(order) => order,
          }
        } {
          ScannerOrder::RotateKey { activation_number, key } => {
            if !self.keys.is_empty() {
              // Protonet will have a single, static validator set
              // TODO
              panic!("only a single key is supported at this time");
            }

            info!("Rotating to key {}", hex::encode(key.to_bytes()));
            assert!(self.db.save_scanned_block(&key, activation_number).is_empty());
            self.db.add_active_key(key);
            self.keys.push(key);
          }

          ScannerOrder::AckBlock(key, id) => {
            debug!("Block {} acknowledged", hex::encode(&id));
            let number = self.db.block_number(&id).expect("node behind");
            for output in self.db.save_scanned_block(&key, number) {
              ram_outputs.remove(output.as_ref());
            }
          }
        }
      }
    }
  }
}
