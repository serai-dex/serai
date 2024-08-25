use core::{marker::PhantomData, fmt::Debug, time::Duration};

use tokio::sync::mpsc;

use serai_primitives::{NetworkId, Coin, Amount};
use primitives::Block;

// Logic for deciding where in its lifetime a multisig is.
mod lifetime;

// Database schema definition and associated functions.
mod db;
// Task to index the blockchain, ensuring we don't reorganize finalized blocks.
mod index;
// Scans blocks for received coins.
mod scan;
/// Check blocks for transactions expected to eventually occur.
mod eventuality;
/// Task which reports `Batch`s to Substrate.
mod report;

/// A feed usable to scan a blockchain.
///
/// This defines the primitive types used, along with various getters necessary for indexing.
#[async_trait::async_trait]
pub trait ScannerFeed: Send + Sync {
  /// The ID of the network being scanned for.
  const NETWORK: NetworkId;

  /// The amount of confirmations a block must have to be considered finalized.
  ///
  /// This value must be at least `1`.
  const CONFIRMATIONS: u64;

  /// The amount of blocks to process in parallel.
  ///
  /// This must be at least `1`. This must be less than or equal to `CONFIRMATIONS`. This value
  /// should be the worst-case latency to handle a block divided by the expected block time.
  const WINDOW_LENGTH: u64;

  /// The amount of blocks which will occur in 10 minutes (approximate).
  ///
  /// This value must be at least `1`.
  const TEN_MINUTES: u64;

  /// The representation of a block for this blockchain.
  ///
  /// A block is defined as a consensus event associated with a set of transactions. It is not
  /// necessary to literally define it as whatever the external network defines as a block. For
  /// external networks which finalize block(s), this block type should be a representation of all
  /// transactions within a finalization event.
  type Block: Block;

  /// An error encountered when fetching data from the blockchain.
  ///
  /// This MUST be an ephemeral error. Retrying fetching data from the blockchain MUST eventually
  /// resolve without manual intervention.
  type EphemeralError: Debug;

  /// Fetch the number of the latest finalized block.
  ///
  /// The block number is its zero-indexed position within a linear view of the external network's
  /// consensus. The genesis block accordingly has block number 0.
  async fn latest_finalized_block_number(&self) -> Result<u64, Self::EphemeralError>;

  /// Fetch a block header by its number.
  async fn block_header_by_number(
    &self,
    number: u64,
  ) -> Result<<Self::Block as Block>::Header, Self::EphemeralError>;

  /// Fetch a block by its number.
  async fn block_by_number(&self, number: u64) -> Result<Self::Block, Self::EphemeralError>;

  /// The cost to aggregate an input as of the specified block.
  ///
  /// This is defined as the transaction fee for a 2-input, 1-output transaction.
  async fn cost_to_aggregate(
    &self,
    coin: Coin,
    block_number: u64,
  ) -> Result<Amount, Self::EphemeralError>;

  /// The dust threshold for the specified coin.
  ///
  /// This MUST be constant. Serai MJUST NOT create internal outputs worth less than this. This
  /// SHOULD be a value worth handling at a human level.
  fn dust(&self, coin: Coin) -> Amount;
}

type KeyFor<S> = <<S as ScannerFeed>::Block as Block>::Key;
type AddressFor<S> = <<S as ScannerFeed>::Block as Block>::Address;
type OutputFor<S> = <<S as ScannerFeed>::Block as Block>::Output;

/// A handle to immediately run an iteration of a task.
#[derive(Clone)]
pub(crate) struct RunNowHandle(mpsc::Sender<()>);
/// An instruction recipient to immediately run an iteration of a task.
pub(crate) struct RunNowRecipient(mpsc::Receiver<()>);

impl RunNowHandle {
  /// Create a new run-now handle to be assigned to a task.
  pub(crate) fn new() -> (Self, RunNowRecipient) {
    // Uses a capacity of 1 as any call to run as soon as possible satisfies all calls to run as
    // soon as possible
    let (send, recv) = mpsc::channel(1);
    (Self(send), RunNowRecipient(recv))
  }

  /// Tell the task to run now (and not whenever its next iteration on a timer is).
  ///
  /// Panics if the task has been dropped.
  pub(crate) fn run_now(&self) {
    #[allow(clippy::match_same_arms)]
    match self.0.try_send(()) {
      Ok(()) => {}
      // NOP on full, as this task will already be ran as soon as possible
      Err(mpsc::error::TrySendError::Full(())) => {}
      Err(mpsc::error::TrySendError::Closed(())) => {
        panic!("task was unexpectedly closed when calling run_now")
      }
    }
  }
}

#[async_trait::async_trait]
pub(crate) trait ContinuallyRan: Sized {
  /// Run an iteration of the task.
  ///
  /// If this returns `true`, all dependents of the task will immediately have a new iteration ran
  /// (without waiting for whatever timer they were already on).
  async fn run_iteration(&mut self) -> Result<bool, String>;

  /// Continually run the task.
  ///
  /// This returns a channel which can have a message set to immediately trigger a new run of an
  /// iteration.
  async fn continually_run(mut self, mut run_now: RunNowRecipient, dependents: Vec<RunNowHandle>) {
    // The default number of seconds to sleep before running the task again
    let default_sleep_before_next_task = 5;
    // The current number of seconds to sleep before running the task again
    // We increment this upon errors in order to not flood the logs with errors
    let mut current_sleep_before_next_task = default_sleep_before_next_task;
    let increase_sleep_before_next_task = |current_sleep_before_next_task: &mut u64| {
      let new_sleep = *current_sleep_before_next_task + default_sleep_before_next_task;
      // Set a limit of sleeping for two minutes
      *current_sleep_before_next_task = new_sleep.max(120);
    };

    loop {
      match self.run_iteration().await {
        Ok(run_dependents) => {
          // Upon a successful (error-free) loop iteration, reset the amount of time we sleep
          current_sleep_before_next_task = default_sleep_before_next_task;

          if run_dependents {
            for dependent in &dependents {
              dependent.run_now();
            }
          }
        }
        Err(e) => {
          log::debug!("{}", e);
          increase_sleep_before_next_task(&mut current_sleep_before_next_task);
        }
      }

      // Don't run the task again for another few seconds UNLESS told to run now
      tokio::select! {
        () = tokio::time::sleep(Duration::from_secs(current_sleep_before_next_task)) => {},
        msg = run_now.0.recv() => assert_eq!(msg, Some(()), "run now handle was dropped"),
      }
    }
  }
}

/// A representation of a scanner.
pub struct Scanner<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> Scanner<S> {
  /// Create a new scanner.
  ///
  /// This will begin its execution, spawning several asynchronous tasks.
  // TODO: Take start_time and binary search here?
  pub fn new(start_block: u64) -> Self {
    todo!("TODO")
  }

  /// Acknowledge a block.
  ///
  /// This means this block was ordered on Serai in relation to `Burn` events, and all validators
  /// have achieved synchrony on it.
  // TODO: If we're acknowledge block `b`, the Eventuality task was already eligible to check it
  // for Eventualities. We need this to block until the Eventuality task has actually checked it.
  pub fn acknowledge_block(
    &mut self,
    block_number: u64,
    key_to_activate: Option<()>,
  ) -> Vec<OutputFor<S>> {
    todo!("TODO")
  }

  /// Register the Eventualities caused by a block.
  // TODO: Replace this with a callback returned by acknowledge_block which panics if it's not
  // called yet dropped
  pub fn register_eventualities(&mut self, block_number: u64, eventualities: Vec<()>) {
    todo!("TODO")
  }
}

/*
#[derive(Clone, Debug)]
pub enum ScannerEvent<N: Network> {
  // Block scanned
  Block {
    is_retirement_block: bool,
    block: <N::Block as Block<N>>::Id,
    outputs: Vec<N::Output>,
  },
  // Eventuality completion found on-chain
  // TODO: Move this from a tuple
  Completed(
    Vec<u8>,
    usize,
    [u8; 32],
    <N::Transaction as Transaction<N>>::Id,
    <N::Eventuality as Eventuality>::Completion,
  ),
}

#[derive(Clone, Debug)]
struct ScannerDb<N: Network, D: Db>(PhantomData<N>, PhantomData<D>);
impl<N: Network, D: Db> ScannerDb<N, D> {
  fn seen_key(id: &<N::Output as Output<N>>::Id) -> Vec<u8> {
    Self::scanner_key(b"seen", id)
  }
  fn seen<G: Get>(getter: &G, id: &<N::Output as Output<N>>::Id) -> bool {
    getter.get(Self::seen_key(id)).is_some()
  }

  fn save_scanned_block(txn: &mut D::Transaction<'_>, block: usize) -> Vec<N::Output> {
    let id = Self::block(txn, block); // It may be None for the first key rotated to
    let outputs =
      if let Some(id) = id.as_ref() { Self::outputs(txn, id).unwrap_or(vec![]) } else { vec![] };

    // Mark all the outputs from this block as seen
    for output in &outputs {
      txn.put(Self::seen_key(&output.id()), b"");
    }

    txn.put(Self::scanned_block_key(), u64::try_from(block).unwrap().to_le_bytes());

    // Return this block's outputs so they can be pruned from the RAM cache
    outputs
  }
  fn latest_scanned_block<G: Get>(getter: &G) -> Option<usize> {
    getter
      .get(Self::scanned_block_key())
      .map(|bytes| u64::from_le_bytes(bytes.try_into().unwrap()).try_into().unwrap())
  }

  fn retirement_block_key(key: &<N::Curve as Ciphersuite>::G) -> Vec<u8> {
    Self::scanner_key(b"retirement_block", key.to_bytes())
  }
  fn save_retirement_block(
    txn: &mut D::Transaction<'_>,
    key: &<N::Curve as Ciphersuite>::G,
    block: usize,
  ) {
    txn.put(Self::retirement_block_key(key), u64::try_from(block).unwrap().to_le_bytes());
  }
  fn retirement_block<G: Get>(getter: &G, key: &<N::Curve as Ciphersuite>::G) -> Option<usize> {
    getter
      .get(Self::retirement_block_key(key))
      .map(|bytes| usize::try_from(u64::from_le_bytes(bytes.try_into().unwrap())).unwrap())
  }
}

impl<N: Network, D: Db> ScannerHandle<N, D> {
  /// Acknowledge having handled a block.
  ///
  /// Creates a lock over the Scanner, preventing its independent scanning operations until
  /// released.
  ///
  /// This must only be called on blocks which have been scanned in-memory.
  pub async fn ack_block(
    &mut self,
    txn: &mut D::Transaction<'_>,
    id: <N::Block as Block<N>>::Id,
  ) -> (bool, Vec<N::Output>) {
    debug!("block {} acknowledged", hex::encode(&id));

    let mut scanner = self.scanner.long_term_acquire().await;

    // Get the number for this block
    let number = ScannerDb::<N, D>::block_number(txn, &id)
      .expect("main loop trying to operate on data we haven't scanned");
    log::trace!("block {} was {number}", hex::encode(&id));

    let outputs = ScannerDb::<N, D>::save_scanned_block(txn, number);
    // This has a race condition if we try to ack a block we scanned on a prior boot, and we have
    // yet to scan it on this boot
    assert!(number <= scanner.ram_scanned.unwrap());
    for output in &outputs {
      assert!(scanner.ram_outputs.remove(output.id().as_ref()));
    }

    assert_eq!(scanner.need_ack.pop_front().unwrap(), number);

    self.held_scanner = Some(scanner);

    // Load the key from the DB, as it will have already been removed from RAM if retired
    let key = ScannerDb::<N, D>::keys(txn)[0].1;
    let is_retirement_block = ScannerDb::<N, D>::retirement_block(txn, &key) == Some(number);
    if is_retirement_block {
      ScannerDb::<N, D>::retire_key(txn);
    }
    (is_retirement_block, outputs)
  }

  pub async fn register_eventuality(
    &mut self,
    key: &[u8],
    block_number: usize,
    id: [u8; 32],
    eventuality: N::Eventuality,
  ) {
    let mut lock;
    // We won't use held_scanner if we're re-registering on boot
    (if let Some(scanner) = self.held_scanner.as_mut() {
      scanner
    } else {
      lock = Some(self.scanner.write().await);
      lock.as_mut().unwrap().as_mut().unwrap()
    })
    .eventualities
    .get_mut(key)
    .unwrap()
    .register(block_number, id, eventuality)
  }

  pub async fn release_lock(&mut self) {
    self.scanner.restore(self.held_scanner.take().unwrap()).await
  }
}

impl<N: Network, D: Db> Scanner<N, D> {
  #[allow(clippy::type_complexity, clippy::new_ret_no_self)]
  pub fn new(
    network: N,
    db: D,
  ) -> (ScannerHandle<N, D>, Vec<(usize, <N::Curve as Ciphersuite>::G)>) {
    let (multisig_completed_send, multisig_completed_recv) = mpsc::unbounded_channel();

    let keys = ScannerDb::<N, D>::keys(&db);
    let mut eventualities = HashMap::new();
    for key in &keys {
      eventualities.insert(key.1.to_bytes().as_ref().to_vec(), EventualitiesTracker::new());
    }
  }

  // An async function, to be spawned on a task, to discover and report outputs
  async fn run(
    mut db: D,
    network: N,
    scanner_hold: ScannerHold<N, D>,
    mut multisig_completed: mpsc::UnboundedReceiver<bool>,
  ) {
    loop {
      for block_being_scanned in (ram_scanned + 1) ..= latest_block_to_scan {
        // Redo the checks for if we're too far ahead
        {
          let needing_ack = {
            let scanner_lock = scanner_hold.read().await;
            let scanner = scanner_lock.as_ref().unwrap();
            scanner.need_ack.front().copied()
          };

          if let Some(needing_ack) = needing_ack {
            let limit = needing_ack + N::CONFIRMATIONS;
            assert!(block_being_scanned <= limit);
            if block_being_scanned == limit {
              break;
            }
          }
        }

        let Ok(block) = network.get_block(block_being_scanned).await else {
          warn!("couldn't get block {block_being_scanned}");
          break;
        };
        let block_id = block.id();

        info!("scanning block: {} ({block_being_scanned})", hex::encode(&block_id));

        // Scan new blocks
        // TODO: This lock acquisition may be long-lived...
        let mut scanner_lock = scanner_hold.write().await;
        let scanner = scanner_lock.as_mut().unwrap();

        let mut has_activation = false;
        let mut outputs = vec![];
        let mut completion_block_numbers = vec![];
        for (activation_number, key) in scanner.keys.clone() {
          if activation_number > block_being_scanned {
            continue;
          }

          if activation_number == block_being_scanned {
            has_activation = true;
          }

          for (id, (block_number, tx, completion)) in network
            .get_eventuality_completions(scanner.eventualities.get_mut(&key_vec).unwrap(), &block)
            .await
          {
            info!(
              "eventuality {} resolved by {}, as found on chain",
              hex::encode(id),
              hex::encode(tx.as_ref())
            );

            completion_block_numbers.push(block_number);
            // This must be before the mission of ScannerEvent::Block, per commentary in mod.rs
            if !scanner.emit(ScannerEvent::Completed(
              key_vec.clone(),
              block_number,
              id,
              tx,
              completion,
            )) {
              return;
            }
          }
        }

        // Panic if we've already seen these outputs
        for output in &outputs {
          let id = output.id();
          info!(
            "block {} had output {} worth {:?}",
            hex::encode(&block_id),
            hex::encode(&id),
            output.balance(),
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

            TODO2: Only update ram_outputs after committing the TXN in question.
          */
          let seen = ScannerDb::<N, D>::seen(&db, &id);
          let id = id.as_ref().to_vec();
          if seen || scanner.ram_outputs.contains(&id) {
            panic!("scanned an output multiple times");
          }
          scanner.ram_outputs.insert(id);
        }

        // We could remove this, if instead of doing the first block which passed
        // requirements + CONFIRMATIONS, we simply emitted an event for every block where
        // `number % CONFIRMATIONS == 0` (once at the final stage for the existing multisig)
        // There's no need at this point, yet the latter may be more suitable for modeling...
        async fn check_multisig_completed<N: Network, D: Db>(
          db: &mut D,
          multisig_completed: &mut mpsc::UnboundedReceiver<bool>,
          block_number: usize,
        ) -> bool {
          match multisig_completed.recv().await {
            None => {
              info!("Scanner handler was dropped. Shutting down?");
              false
            }
            Some(completed) => {
              // Set the retirement block as block_number + CONFIRMATIONS
              if completed {
                let mut txn = db.txn();
                // The retiring key is the earliest one still around
                let retiring_key = ScannerDb::<N, D>::keys(&txn)[0].1;
                // This value is static w.r.t. the key
                ScannerDb::<N, D>::save_retirement_block(
                  &mut txn,
                  &retiring_key,
                  block_number + N::CONFIRMATIONS,
                );
                txn.commit();
              }
              true
            }
          }
        }

        drop(scanner_lock);
        // Now that we've dropped the Scanner lock, we need to handle the multisig_completed
        // channel before we decide if this block should be fired or not
        // (holding the Scanner risks a deadlock)
        for block_number in completion_block_numbers {
          if !check_multisig_completed::<N, _>(&mut db, &mut multisig_completed, block_number).await
          {
            return;
          };
        }

        // Reacquire the scanner
        let mut scanner_lock = scanner_hold.write().await;
        let scanner = scanner_lock.as_mut().unwrap();

        // Only emit an event if any of the following is true:
        // - This is an activation block
        // - This is a retirement block
        // - There's outputs
        // as only those blocks are meaningful and warrant obtaining synchrony over
        let is_retirement_block =
          ScannerDb::<N, D>::retirement_block(&db, &scanner.keys[0].1) == Some(block_being_scanned);
        let sent_block = if has_activation || is_retirement_block || (!outputs.is_empty()) {
          // Save the outputs to disk
          let mut txn = db.txn();
          ScannerDb::<N, D>::save_outputs(&mut txn, &block_id, &outputs);
          txn.commit();

          // Send all outputs
          if !scanner.emit(ScannerEvent::Block { is_retirement_block, block: block_id, outputs }) {
            return;
          }

          // Since we're creating a Batch, mark it as needing ack
          scanner.need_ack.push_back(block_being_scanned);
          true
        } else {
          false
        };

        // Remove it from memory
        if is_retirement_block {
          let retired = scanner.keys.remove(0).1;
          scanner.eventualities.remove(retired.to_bytes().as_ref());
        }
        drop(scanner_lock);
        // If we sent a Block event, once again check multisig_completed
        if sent_block &&
          (!check_multisig_completed::<N, _>(
            &mut db,
            &mut multisig_completed,
            block_being_scanned,
          )
          .await)
        {
          return;
        }
      }
    }
  }
}
*/
