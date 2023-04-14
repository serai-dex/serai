use core::marker::PhantomData;
use std::{
  sync::Arc,
  time::{SystemTime, Duration},
  collections::{HashSet, HashMap},
};

use group::GroupEncoding;
use frost::curve::Ciphersuite;

use log::{info, debug, warn};
use tokio::{
  sync::{RwLock, mpsc},
  time::sleep,
};

use crate::{
  Get, DbTxn, Db,
  coins::{Output, Transaction, EventualitiesTracker, Block, Coin},
};

#[derive(Clone, Debug)]
pub enum ScannerEvent<C: Coin> {
  // Block scanned
  Block {
    key: <C::Curve as Ciphersuite>::G,
    block: <C::Block as Block<C>>::Id,
    time: SystemTime,
    batch: u32,
    outputs: Vec<C::Output>,
  },
  // Eventuality completion found on-chain
  Completed([u8; 32], <C::Transaction as Transaction<C>>::Id),
}

pub type ScannerEventChannel<C> = mpsc::UnboundedReceiver<ScannerEvent<C>>;

#[derive(Clone, Debug)]
struct ScannerDb<C: Coin, D: Db>(D, PhantomData<C>);
impl<C: Coin, D: Db> ScannerDb<C, D> {
  fn scanner_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"SCANNER", dst, key)
  }

  fn block_key(number: usize) -> Vec<u8> {
    Self::scanner_key(b"block_id", u64::try_from(number).unwrap().to_le_bytes())
  }
  fn block_number_key(id: &<C::Block as Block<C>>::Id) -> Vec<u8> {
    Self::scanner_key(b"block_number", id)
  }
  fn save_block(txn: &mut D::Transaction<'_>, number: usize, id: &<C::Block as Block<C>>::Id) {
    txn.put(Self::block_number_key(id), u64::try_from(number).unwrap().to_le_bytes());
    txn.put(Self::block_key(number), id);
  }
  fn block<G: Get>(getter: &G, number: usize) -> Option<<C::Block as Block<C>>::Id> {
    getter.get(Self::block_key(number)).map(|id| {
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
  fn add_active_key(txn: &mut D::Transaction<'_>, key: <C::Curve as Ciphersuite>::G) {
    let mut keys = txn.get(Self::active_keys_key()).unwrap_or(vec![]);

    let key_bytes = key.to_bytes();

    let key_len = key_bytes.as_ref().len();
    assert_eq!(keys.len() % key_len, 0);

    // Don't add this key if it's already present
    let mut i = 0;
    while i < keys.len() {
      if &keys[i .. (i + key_len)] == key_bytes.as_ref() {
        debug!("adding {} as an active key yet it was already present", hex::encode(key_bytes));
        return;
      }
      i += key_len;
    }

    keys.extend(key_bytes.as_ref());
    txn.put(Self::active_keys_key(), keys);
  }
  fn active_keys(&self) -> Vec<<C::Curve as Ciphersuite>::G> {
    let bytes_vec = self.0.get(Self::active_keys_key()).unwrap_or(vec![]);
    let mut bytes: &[u8] = bytes_vec.as_ref();

    // Assumes keys will be 32 bytes when calculating the capacity
    // If keys are larger, this may allocate more memory than needed
    // If keys are smaller, this may require additional allocations
    // Either are fine
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

  fn next_batch_key() -> Vec<u8> {
    Self::scanner_key(b"next_batch", [])
  }
  fn batch_key(key: &<C::Curve as Ciphersuite>::G, block: &<C::Block as Block<C>>::Id) -> Vec<u8> {
    Self::scanner_key(b"batch", [key.to_bytes().as_ref(), block.as_ref()].concat())
  }
  fn outputs_key(
    key: &<C::Curve as Ciphersuite>::G,
    block: &<C::Block as Block<C>>::Id,
  ) -> Vec<u8> {
    Self::scanner_key(b"outputs", [key.to_bytes().as_ref(), block.as_ref()].concat())
  }
  fn save_outputs(
    txn: &mut D::Transaction<'_>,
    key: &<C::Curve as Ciphersuite>::G,
    block: &<C::Block as Block<C>>::Id,
    outputs: &[C::Output],
  ) -> u32 {
    let batch_key = Self::batch_key(key, block);
    if let Some(batch) = txn.get(batch_key) {
      return u32::from_le_bytes(batch.try_into().unwrap());
    }

    let mut bytes = Vec::with_capacity(outputs.len() * 64);
    for output in outputs {
      output.write(&mut bytes).unwrap();
    }
    txn.put(Self::outputs_key(key, block), bytes);

    // This is a new set of outputs, which are expected to be handled in a perfectly ordered
    // fashion

    // TODO2: This is not currently how this works
    // There may be new blocks 0 .. 5, which A will scan, yet then B may be activated at block 4
    // This would cause
    // 0a, 1a, 2a, 3a, 4a, 5a, 4b, 5b
    // when it should be
    // 0a, 1a, 2a, 3a, 4a, 4b, 5a, 5b

    // Because it's a new set of outputs, allocate a batch ID for it
    let next_bytes = txn.get(Self::next_batch_key()).unwrap_or(vec![0; 4]).try_into().unwrap();
    let next = u32::from_le_bytes(next_bytes);
    txn.put(Self::next_batch_key(), (next + 1).to_le_bytes());
    txn.put(Self::batch_key(key, block), next_bytes);
    next
  }
  fn outputs(
    txn: &D::Transaction<'_>,
    key: &<C::Curve as Ciphersuite>::G,
    block: &<C::Block as Block<C>>::Id,
  ) -> Option<Vec<C::Output>> {
    let bytes_vec = txn.get(Self::outputs_key(key, block))?;
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
    txn: &mut D::Transaction<'_>,
    key: &<C::Curve as Ciphersuite>::G,
    block: usize,
  ) -> Vec<C::Output> {
    let new_key = txn.get(Self::scanned_block_key(key)).is_none();
    let outputs = Self::block(txn, block).and_then(|id| Self::outputs(txn, key, &id));
    // Either this is a new key, with no outputs, or we're acknowledging this block
    // If we're acknowledging it, we should have outputs available
    assert_eq!(new_key, outputs.is_none());
    let outputs = outputs.unwrap_or(vec![]);

    // Mark all the outputs from this block as seen
    for output in &outputs {
      txn.put(Self::seen_key(&output.id()), b"");
    }

    txn.put(Self::scanned_block_key(key), u64::try_from(block).unwrap().to_le_bytes());

    // Return this block's outputs so they can be pruned from the RAM cache
    outputs
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

  eventualities: EventualitiesTracker<C::Eventuality>,

  ram_scanned: HashMap<Vec<u8>, usize>,
  ram_outputs: HashSet<Vec<u8>>,

  events: mpsc::UnboundedSender<ScannerEvent<C>>,
}

#[derive(Debug)]
pub struct ScannerHandle<C: Coin, D: Db> {
  scanner: Arc<RwLock<Scanner<C, D>>>,
  pub events: ScannerEventChannel<C>,
}

impl<C: Coin, D: Db> ScannerHandle<C, D> {
  pub async fn ram_scanned(&self) -> usize {
    let mut res = None;
    for scanned in self.scanner.read().await.ram_scanned.values() {
      if res.is_none() {
        res = Some(*scanned);
      }
      // Returns the lowest scanned value so no matter the keys interacted with, this is
      // sufficiently scanned
      res = Some(res.unwrap().min(*scanned));
    }
    res.unwrap_or(0)
  }

  pub async fn register_eventuality(
    &self,
    block_number: usize,
    id: [u8; 32],
    eventuality: C::Eventuality,
  ) {
    self.scanner.write().await.eventualities.register(block_number, id, eventuality)
  }

  pub async fn drop_eventuality(&self, id: [u8; 32]) {
    self.scanner.write().await.eventualities.drop(id);
  }

  /// Rotate the key being scanned for.
  ///
  /// If no key has been prior set, this will become the key with no further actions.
  ///
  /// If a key has been prior set, both keys will be scanned for as detailed in the Multisig
  /// documentation. The old key will eventually stop being scanned for, leaving just the
  /// updated-to key.
  pub async fn rotate_key(&self, activation_number: usize, key: <C::Curve as Ciphersuite>::G) {
    let mut scanner = self.scanner.write().await;
    if !scanner.keys.is_empty() {
      // Protonet will have a single, static validator set
      // TODO2
      panic!("only a single key is supported at this time");
    }

    info!("Rotating to key {}", hex::encode(key.to_bytes()));
    let mut txn = scanner.db.0.txn();
    assert!(ScannerDb::<C, D>::save_scanned_block(&mut txn, &key, activation_number).is_empty());
    ScannerDb::<C, D>::add_active_key(&mut txn, key);
    txn.commit();
    scanner.keys.push(key);
  }

  pub async fn block_number(&self, id: &<C::Block as Block<C>>::Id) -> Option<usize> {
    self.scanner.read().await.db.block_number(id)
  }

  /// Acknowledge having handled a block for a key.
  pub async fn ack_block(
    &self,
    key: <C::Curve as Ciphersuite>::G,
    id: <C::Block as Block<C>>::Id,
  ) -> Vec<C::Output> {
    let mut scanner = self.scanner.write().await;
    debug!("Block {} acknowledged", hex::encode(&id));
    let number =
      scanner.db.block_number(&id).expect("main loop trying to operate on data we haven't scanned");

    let mut txn = scanner.db.0.txn();
    let outputs = ScannerDb::<C, D>::save_scanned_block(&mut txn, &key, number);
    txn.commit();

    for output in &outputs {
      scanner.ram_outputs.remove(output.id().as_ref());
    }

    outputs
  }
}

impl<C: Coin, D: Db> Scanner<C, D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(coin: C, db: D) -> (ScannerHandle<C, D>, Vec<<C::Curve as Ciphersuite>::G>) {
    let (events_send, events_recv) = mpsc::unbounded_channel();

    let db = ScannerDb(db, PhantomData);
    let keys = db.active_keys();

    let scanner = Arc::new(RwLock::new(Scanner {
      coin,
      db,
      keys: keys.clone(),

      eventualities: EventualitiesTracker::new(),

      ram_scanned: HashMap::new(),
      ram_outputs: HashSet::new(),

      events: events_send,
    }));
    tokio::spawn(Scanner::run(scanner.clone()));

    (ScannerHandle { scanner, events: events_recv }, keys)
  }

  fn emit(&mut self, event: ScannerEvent<C>) -> bool {
    if self.events.send(event).is_err() {
      info!("Scanner handler was dropped. Shutting down?");
      return false;
    }
    true
  }

  // An async function, to be spawned on a task, to discover and report outputs
  async fn run(scanner: Arc<RwLock<Self>>) {
    loop {
      // Only check every five seconds for new blocks
      sleep(Duration::from_secs(5)).await;

      // Scan new blocks
      {
        let mut scanner = scanner.write().await;
        let latest = scanner.coin.get_latest_block_number().await;
        let latest = match latest {
          // Only scan confirmed blocks, which we consider effectively finalized
          // CONFIRMATIONS - 1 as whatever's in the latest block already has 1 confirm
          Ok(latest) => latest.saturating_sub(C::CONFIRMATIONS.saturating_sub(1)),
          Err(_) => {
            warn!("couldn't get latest block number");
            sleep(Duration::from_secs(60)).await;
            continue;
          }
        };

        for key in scanner.keys.clone() {
          let key_vec = key.to_bytes().as_ref().to_vec();
          let latest_scanned = {
            // Grab the latest scanned block according to the DB
            let db_scanned = scanner.db.latest_scanned_block(key);
            // We may, within this process's lifetime, have scanned more blocks
            // If they're still being processed, we will not have officially written them to the DB
            // as scanned yet
            // That way, if the process terminates, and is rebooted, we'll rescan from a handled
            // point, re-firing all events along the way, enabling them to be properly processed
            // In order to not re-fire them within this process's lifetime, check our RAM cache
            // of what we've scanned
            // We are allowed to re-fire them within this lifetime. It's just wasteful
            let ram_scanned = scanner.ram_scanned.get(&key_vec).cloned().unwrap_or(0);
            // Pick whichever is higher
            db_scanned.max(ram_scanned)
          };

          for i in (latest_scanned + 1) ..= latest {
            // TODO2: Check for key deprecation

            let block = match scanner.coin.get_block(i).await {
              Ok(block) => block,
              Err(_) => {
                warn!("couldn't get block {i}");
                break;
              }
            };
            let block_id = block.id();

            if let Some(id) = ScannerDb::<C, D>::block(&scanner.db.0, i) {
              // TODO2: Also check this block builds off the previous block
              if id != block_id {
                panic!("reorg'd from finalized {} to {}", hex::encode(id), hex::encode(block_id));
              }
            } else {
              info!("Found new block: {}", hex::encode(&block_id));
              let mut txn = scanner.db.0.txn();
              ScannerDb::<C, D>::save_block(&mut txn, i, &block_id);
              txn.commit();
            }

            // Clone coin because we can't borrow it while also mutably borrowing the eventualities
            // Thankfully, coin is written to be a cheap clone
            let coin = scanner.coin.clone();
            for (id, tx) in
              coin.get_eventuality_completions(&mut scanner.eventualities, &block).await
            {
              // This should only happen if there's a P2P net desync or there's a malicious
              // validator
              warn!(
                "eventuality {} resolved by {}, as found on chain. this should not happen",
                hex::encode(id),
                hex::encode(&tx)
              );

              if !scanner.emit(ScannerEvent::Completed(id, tx)) {
                return;
              }
            }

            let outputs = match scanner.coin.get_outputs(&block, key).await {
              Ok(outputs) => outputs,
              Err(_) => {
                warn!("Couldn't scan block {i}");
                break;
              }
            };

            // Panic if we've already seen these outputs
            for output in &outputs {
              let id = output.id();
              info!(
                "block {} had output {} worth {}",
                hex::encode(&block_id),
                hex::encode(&id),
                output.amount(),
              );

              // On Bitcoin, the output ID should be unique for a given chain
              // On Monero, it's trivial to make an output sharing an ID with another
              // We should only scan outputs with valid IDs however, which will be unique
              let seen = scanner.db.seen(&id);
              let id = id.as_ref().to_vec();
              if seen || scanner.ram_outputs.contains(&id) {
                panic!("scanned an output multiple times");
              }
              scanner.ram_outputs.insert(id);
            }

            if outputs.is_empty() {
              continue;
            }

            // Save the outputs to disk
            let mut txn = scanner.db.0.txn();
            let batch = ScannerDb::<C, D>::save_outputs(&mut txn, &key, &block_id, &outputs);
            txn.commit();

            const TIME_TOLERANCE: u64 = 15;

            let now = SystemTime::now();
            let mut time = block.time();

            // Block is older than the tolerance
            // This isn't an issue, yet shows our daemon may have fallen behind/been disconnected
            if now.duration_since(time).unwrap_or(Duration::ZERO) >
              Duration::from_secs(TIME_TOLERANCE)
            {
              warn!(
                "the time is {} and we only just received a block dated {}",
                (now.duration_since(SystemTime::UNIX_EPOCH)).expect("now before epoch").as_secs(),
                (time.duration_since(SystemTime::UNIX_EPOCH))
                  .expect("block time before epoch")
                  .as_secs(),
              );
            }

            // If this block is in the future, either this server's clock is wrong OR the block's
            // miner's clock is wrong. The latter is the problem
            //
            // This time is used to schedule signing sessions over the content of this block
            // If it's in the future, the first attempt won't time out until this block is no
            // longer in the future
            //
            // Since we don't need consensus, if this time is more than 15s in the future,
            // set it to the local time
            //
            // As long as a supermajority of nodes set a time within ~15s of each other, this
            // should be fine

            // TODO2: Make more robust
            if time.duration_since(now).unwrap_or(Duration::ZERO) >
              Duration::from_secs(TIME_TOLERANCE)
            {
              time = now;
            }

            // Send all outputs
            if !scanner.emit(ScannerEvent::Block { key, block: block_id, time, batch, outputs }) {
              return;
            }
            // Write this number as scanned so we won't re-fire these outputs
            scanner.ram_scanned.insert(key_vec.clone(), i);
          }
        }
      }
    }
  }
}
