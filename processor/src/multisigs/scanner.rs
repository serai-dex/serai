use core::marker::PhantomData;
use std::{
  sync::Arc,
  time::Duration,
  collections::{HashSet, HashMap},
};

use ciphersuite::group::GroupEncoding;
use frost::curve::Ciphersuite;

use log::{info, debug, warn};
use tokio::{
  sync::{RwLock, mpsc},
  time::sleep,
};

use crate::{
  Get, DbTxn, Db,
  networks::{Output, Transaction, EventualitiesTracker, Block, Network},
};

#[derive(Clone, Debug)]
pub enum ScannerEvent<N: Network> {
  // Block scanned
  Block { block: <N::Block as Block<N>>::Id, outputs: Vec<N::Output> },
  // Eventuality completion found on-chain
  Completed(Vec<u8>, [u8; 32], <N::Transaction as Transaction<N>>::Id),
}

pub type ScannerEventChannel<N> = mpsc::UnboundedReceiver<ScannerEvent<N>>;

#[derive(Clone, Debug)]
struct ScannerDb<N: Network, D: Db>(PhantomData<N>, PhantomData<D>);
impl<N: Network, D: Db> ScannerDb<N, D> {
  fn scanner_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"SCANNER", dst, key)
  }

  fn block_key(number: usize) -> Vec<u8> {
    Self::scanner_key(b"block_id", u64::try_from(number).unwrap().to_le_bytes())
  }
  fn block_number_key(id: &<N::Block as Block<N>>::Id) -> Vec<u8> {
    Self::scanner_key(b"block_number", id)
  }
  // TODO: On boot, do this for all outstanding blocks
  fn save_block(txn: &mut D::Transaction<'_>, number: usize, id: &<N::Block as Block<N>>::Id) {
    txn.put(Self::block_number_key(id), u64::try_from(number).unwrap().to_le_bytes());
    txn.put(Self::block_key(number), id);
  }
  fn block<G: Get>(getter: &G, number: usize) -> Option<<N::Block as Block<N>>::Id> {
    getter.get(Self::block_key(number)).map(|id| {
      let mut res = <N::Block as Block<N>>::Id::default();
      res.as_mut().copy_from_slice(&id);
      res
    })
  }
  fn block_number<G: Get>(getter: &G, id: &<N::Block as Block<N>>::Id) -> Option<usize> {
    getter
      .get(Self::block_number_key(id))
      .map(|number| u64::from_le_bytes(number.try_into().unwrap()).try_into().unwrap())
  }

  fn active_keys_key() -> Vec<u8> {
    Self::scanner_key(b"active_keys", b"")
  }
  fn add_active_key(txn: &mut D::Transaction<'_>, key: <N::Curve as Ciphersuite>::G) {
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
  fn active_keys<G: Get>(getter: &G) -> Vec<<N::Curve as Ciphersuite>::G> {
    let bytes_vec = getter.get(Self::active_keys_key()).unwrap_or(vec![]);
    let mut bytes: &[u8] = bytes_vec.as_ref();

    // Assumes keys will be 32 bytes when calculating the capacity
    // If keys are larger, this may allocate more memory than needed
    // If keys are smaller, this may require additional allocations
    // Either are fine
    let mut res = Vec::with_capacity(bytes.len() / 32);
    while !bytes.is_empty() {
      res.push(N::Curve::read_G(&mut bytes).unwrap());
    }
    res
  }

  fn seen_key(id: &<N::Output as Output>::Id) -> Vec<u8> {
    Self::scanner_key(b"seen", id)
  }
  fn seen<G: Get>(getter: &G, id: &<N::Output as Output>::Id) -> bool {
    getter.get(Self::seen_key(id)).is_some()
  }

  fn next_batch_key() -> Vec<u8> {
    Self::scanner_key(b"next_batch", [])
  }
  fn outputs_key(
    key: &<N::Curve as Ciphersuite>::G,
    block: &<N::Block as Block<N>>::Id,
  ) -> Vec<u8> {
    Self::scanner_key(b"outputs", [key.to_bytes().as_ref(), block.as_ref()].concat())
  }
  fn save_outputs(
    txn: &mut D::Transaction<'_>,
    key: &<N::Curve as Ciphersuite>::G,
    block: &<N::Block as Block<N>>::Id,
    outputs: &[N::Output],
  ) {
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
  }
  fn outputs(
    txn: &D::Transaction<'_>,
    key: &<N::Curve as Ciphersuite>::G,
    block: &<N::Block as Block<N>>::Id,
  ) -> Option<Vec<N::Output>> {
    let bytes_vec = txn.get(Self::outputs_key(key, block))?;
    let mut bytes: &[u8] = bytes_vec.as_ref();

    let mut res = vec![];
    while !bytes.is_empty() {
      res.push(N::Output::read(&mut bytes).unwrap());
    }
    Some(res)
  }

  fn scanned_block_key(key: &<N::Curve as Ciphersuite>::G) -> Vec<u8> {
    Self::scanner_key(b"scanned_block", key.to_bytes())
  }

  #[allow(clippy::type_complexity)]
  fn save_scanned_block(
    txn: &mut D::Transaction<'_>,
    key: &<N::Curve as Ciphersuite>::G,
    block: usize,
  ) -> Vec<N::Output> {
    let id = Self::block(txn, block); // It may be None for the first key rotated to
    let outputs = if let Some(id) = id.as_ref() {
      Self::outputs(txn, key, id).unwrap_or(vec![])
    } else {
      vec![]
    };

    // Mark all the outputs from this block as seen
    for output in &outputs {
      txn.put(Self::seen_key(&output.id()), b"");
    }

    txn.put(Self::scanned_block_key(key), u64::try_from(block).unwrap().to_le_bytes());

    // Return this block's outputs so they can be pruned from the RAM cache
    outputs
  }
  fn latest_scanned_block<G: Get>(getter: &G, key: <N::Curve as Ciphersuite>::G) -> usize {
    let bytes = getter
      .get(Self::scanned_block_key(&key))
      .expect("asking for latest scanned block of key which wasn't rotated to");
    u64::from_le_bytes(bytes.try_into().unwrap()).try_into().unwrap()
  }
}

/// The Scanner emits events relating to the blockchain, notably received outputs.
///
/// It WILL NOT fail to emit an event, even if it reboots at selected moments.
///
/// It MAY fire the same event multiple times.
#[derive(Debug)]
pub struct Scanner<N: Network, D: Db> {
  network: N,
  db: D,
  keys: Vec<<N::Curve as Ciphersuite>::G>,

  eventualities: HashMap<Vec<u8>, EventualitiesTracker<N::Eventuality>>,

  ram_scanned: HashMap<Vec<u8>, usize>,
  ram_outputs: HashSet<Vec<u8>>,

  events: mpsc::UnboundedSender<ScannerEvent<N>>,
}

#[derive(Debug)]
pub struct ScannerHandle<N: Network, D: Db> {
  scanner: Arc<RwLock<Scanner<N, D>>>,
  pub events: ScannerEventChannel<N>,
}

impl<N: Network, D: Db> ScannerHandle<N, D> {
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
    &mut self,
    key: &[u8],
    block_number: usize,
    id: [u8; 32],
    eventuality: N::Eventuality,
  ) {
    self.scanner.write().await.eventualities.get_mut(key).unwrap().register(
      block_number,
      id,
      eventuality,
    )
  }

  /// Register a key to scan for.
  pub async fn register_key(
    &mut self,
    txn: &mut D::Transaction<'_>,
    activation_number: usize,
    key: <N::Curve as Ciphersuite>::G,
  ) {
    let mut scanner = self.scanner.write().await;
    if !scanner.keys.is_empty() {
      // Protonet will have a single, static validator set
      // TODO2
      panic!("only a single key is supported at this time");
    }

    info!("Registering key {} in scanner at {activation_number}", hex::encode(key.to_bytes()));

    let outputs = ScannerDb::<N, D>::save_scanned_block(txn, &key, activation_number);
    let key_vec = key.to_bytes().as_ref().to_vec();
    scanner.ram_scanned.insert(key_vec.clone(), activation_number);
    assert!(outputs.is_empty());

    ScannerDb::<N, D>::add_active_key(txn, key);
    scanner.keys.push(key);

    scanner.eventualities.insert(key_vec, EventualitiesTracker::new());
  }

  // This perform a database read which isn't safe with regards to if the value is set or not
  // It may be set, when it isn't expected to be set, or not set, when it is expected to be set
  // Since the value is static, if it's set, it's correctly set
  pub async fn block_number(&self, id: &<N::Block as Block<N>>::Id) -> Option<usize> {
    ScannerDb::<N, D>::block_number(&self.scanner.read().await.db, id)
  }

  // Set the next batch ID to use
  pub fn set_next_batch_id(&self, txn: &mut D::Transaction<'_>, batch: u32) {
    txn.put(ScannerDb::<N, D>::next_batch_key(), batch.to_le_bytes());
  }

  // Get the next batch ID
  pub fn next_batch_id(&self, txn: &D::Transaction<'_>) -> u32 {
    txn
      .get(ScannerDb::<N, D>::next_batch_key())
      .map_or(0, |v| u32::from_le_bytes(v.try_into().unwrap()))
  }

  /// Acknowledge having handled a block for a key.
  pub async fn ack_up_to_block(
    &mut self,
    txn: &mut D::Transaction<'_>,
    key: <N::Curve as Ciphersuite>::G,
    id: <N::Block as Block<N>>::Id,
  ) -> Vec<N::Output> {
    let mut scanner = self.scanner.write().await;
    debug!("Block {} acknowledged", hex::encode(&id));

    // Get the number for this block
    let number = ScannerDb::<N, D>::block_number(txn, &id)
      .expect("main loop trying to operate on data we haven't scanned");
    // Get the number of the last block we acknowledged
    let prior = ScannerDb::<N, D>::latest_scanned_block(txn, key);

    let mut outputs = vec![];
    for number in (prior + 1) ..= number {
      outputs.extend(ScannerDb::<N, D>::save_scanned_block(txn, &key, number));
    }

    for output in &outputs {
      assert!(scanner.ram_outputs.remove(output.id().as_ref()));
    }

    outputs
  }
}

impl<N: Network, D: Db> Scanner<N, D> {
  #[allow(clippy::new_ret_no_self)]
  pub fn new(network: N, db: D) -> (ScannerHandle<N, D>, Vec<<N::Curve as Ciphersuite>::G>) {
    let (events_send, events_recv) = mpsc::unbounded_channel();

    let keys = ScannerDb::<N, D>::active_keys(&db);
    let mut ram_scanned = HashMap::new();
    let mut eventualities = HashMap::new();
    for key in keys.clone() {
      let key_vec = key.to_bytes().as_ref().to_vec();
      ram_scanned.insert(key_vec.clone(), ScannerDb::<N, D>::latest_scanned_block(&db, key));
      eventualities.insert(key_vec, EventualitiesTracker::new());
    }

    let scanner = Arc::new(RwLock::new(Scanner {
      network,
      db,
      keys: keys.clone(),

      eventualities,

      ram_scanned,
      ram_outputs: HashSet::new(),

      events: events_send,
    }));
    tokio::spawn(Scanner::run(scanner.clone()));

    (ScannerHandle { scanner, events: events_recv }, keys)
  }

  fn emit(&mut self, event: ScannerEvent<N>) -> bool {
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
        let latest = scanner.network.get_latest_block_number().await;
        let latest = match latest {
          // Only scan confirmed blocks, which we consider effectively finalized
          // CONFIRMATIONS - 1 as whatever's in the latest block already has 1 confirm
          Ok(latest) => latest.saturating_sub(N::CONFIRMATIONS.saturating_sub(1)),
          Err(_) => {
            warn!("couldn't get latest block number");
            sleep(Duration::from_secs(60)).await;
            continue;
          }
        };

        for key in scanner.keys.clone() {
          let key_vec = key.to_bytes().as_ref().to_vec();
          let latest_scanned = scanner.ram_scanned[&key_vec];

          for i in (latest_scanned + 1) ..= latest {
            // TODO2: Check for key deprecation

            let block = match scanner.network.get_block(i).await {
              Ok(block) => block,
              Err(_) => {
                warn!("couldn't get block {i}");
                break;
              }
            };
            let block_id = block.id();

            // These block calls are safe, despite not having a txn, since they're static values
            // only written to/read by this thread
            // There's also no error caused by them being unexpectedly written (if the commit is
            // made and then the processor suddenly reboots)
            // There's also no issue if this code is run multiple times (due to code after
            // aborting)
            if let Some(id) = ScannerDb::<N, D>::block(&scanner.db, i) {
              if id != block_id {
                panic!("reorg'd from finalized {} to {}", hex::encode(id), hex::encode(block_id));
              }
            } else {
              info!("Found new block: {}", hex::encode(&block_id));

              if let Some(id) = ScannerDb::<N, D>::block(&scanner.db, i.saturating_sub(1)) {
                if id != block.parent() {
                  panic!(
                    "block {} doesn't build off expected parent {}",
                    hex::encode(block_id),
                    hex::encode(id),
                  );
                }
              }

              let mut txn = scanner.db.txn();
              ScannerDb::<N, D>::save_block(&mut txn, i, &block_id);
              txn.commit();
            }

            let outputs = match scanner.network.get_outputs(&block, key).await {
              Ok(outputs) => outputs,
              Err(_) => {
                warn!("couldn't scan block {i}");
                break;
              }
            };

            // Write this number as scanned so we won't perform any of the following mutations
            // multiple times
            scanner.ram_scanned.insert(key_vec.clone(), i);

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

              /*
                The safety of this code must satisfy the following conditions:
                1) seen is not set for the first occurrence
                2) seen is set for any future occurrence

                seen is only written to after this code completes. Accordingly, it cannot be set
                before the first occurrence UNLESSS it's set, yet the last scanned block isn't.
                They are both written in the same database transaction, preventing this.

                As for future occurrences, the RAM entry ensures they're handled properly even if
                the database has yet to be set.

                On reboot, which will clear the RAM, if seen wasn't set, neither was latest scanned
                block. Accordingly, this will scan from some prior block, re-populating the RAM.

                If seen was set, then this will be successfully read.

                There's also no concern ram_outputs was pruned, yet seen wasn't set, as pruning
                from ram_outputs will acquire a write lock (preventing this code from acquiring
                its own write lock and running), and during its holding of the write lock, it
                commits the transaction setting seen and the latest scanned block.

                This last case isn't true. Committing seen/latest_scanned_block happens after
                relinquishing the write lock.

                TODO: Only update ram_outputs after committing the TXN in question.
              */
              let seen = ScannerDb::<N, D>::seen(&scanner.db, &id);
              let id = id.as_ref().to_vec();
              if seen || scanner.ram_outputs.contains(&id) {
                panic!("scanned an output multiple times");
              }
              scanner.ram_outputs.insert(id);
            }

            // Clone network because we can't borrow it while also mutably borrowing the
            // eventualities
            // Thankfully, network is written to be a cheap clone
            let network = scanner.network.clone();
            for (id, tx) in network
              .get_eventuality_completions(scanner.eventualities.get_mut(&key_vec).unwrap(), &block)
              .await
            {
              info!(
                "eventuality {} resolved by {}, as found on chain",
                hex::encode(id),
                hex::encode(&tx)
              );

              if !scanner.emit(ScannerEvent::Completed(key_vec.clone(), id, tx)) {
                return;
              }
            }

            // Don't emit an event if there's not any outputs
            // TODO: Still emit an event if activation block or retirement block
            if outputs.is_empty() {
              continue;
            }

            // Save the outputs to disk
            let mut txn = scanner.db.txn();
            ScannerDb::<N, D>::save_outputs(&mut txn, &key, &block_id, &outputs);
            txn.commit();

            // Send all outputs
            // TODO: Block scanning `b + CONFIRMATIONS` until until Substrate acks this Block
            // TODO: Fire this with all outputs for all keys, not for each key
            if !scanner.emit(ScannerEvent::Block { block: block_id, outputs }) {
              return;
            }
          }
        }
      }
    }
  }
}
