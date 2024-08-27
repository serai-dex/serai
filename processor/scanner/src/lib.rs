use core::{marker::PhantomData, fmt::Debug};
use std::collections::HashMap;

use group::GroupEncoding;

use serai_db::{Get, DbTxn};

use serai_primitives::{NetworkId, Coin, Amount};

use primitives::{task::*, Address, ReceivedOutput, Block};

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

pub(crate) fn sort_outputs<K: GroupEncoding, A: Address, O: ReceivedOutput<K, A>>(
  a: &O,
  b: &O,
) -> core::cmp::Ordering {
  use core::cmp::{Ordering, Ord};
  let res = a.id().as_ref().cmp(b.id().as_ref());
  assert!(res != Ordering::Equal, "two outputs within a collection had the same ID");
  res
}

/// Extension traits around Block.
pub(crate) trait BlockExt: Block {
  fn scan_for_outputs(&self, key: Self::Key) -> Vec<Self::Output>;
}
impl<B: Block> BlockExt for B {
  fn scan_for_outputs(&self, key: Self::Key) -> Vec<Self::Output> {
    let mut outputs = self.scan_for_outputs_unordered(key);
    outputs.sort_by(sort_outputs);
    outputs
  }
}

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
  ///
  /// This does not check the returned BlockHeader is the header for the block we indexed.
  async fn unchecked_block_header_by_number(
    &self,
    number: u64,
  ) -> Result<<Self::Block as Block>::Header, Self::EphemeralError>;

  /// Fetch a block by its number.
  ///
  /// This does not check the returned Block is the block we indexed.
  async fn unchecked_block_by_number(
    &self,
    number: u64,
  ) -> Result<Self::Block, Self::EphemeralError>;

  /// Fetch a block by its number.
  ///
  /// Panics if the block requested wasn't indexed.
  async fn block_by_number(
    &self,
    getter: &(impl Send + Sync + Get),
    number: u64,
  ) -> Result<Self::Block, String> {
    let block = match self.unchecked_block_by_number(number).await {
      Ok(block) => block,
      Err(e) => Err(format!("couldn't fetch block {number}: {e:?}"))?,
    };

    // Check the ID of this block is the expected ID
    {
      let expected = crate::index::block_id(getter, number);
      if block.id() != expected {
        panic!(
          "finalized chain reorganized from {} to {} at {}",
          hex::encode(expected),
          hex::encode(block.id()),
          number,
        );
      }
    }

    Ok(block)
  }

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
type EventualityFor<S> = <<S as ScannerFeed>::Block as Block>::Eventuality;

/// A return to occur.
pub struct Return<S: ScannerFeed> {
  address: AddressFor<S>,
  output: OutputFor<S>,
}

/// An update for the scheduler.
pub struct SchedulerUpdate<S: ScannerFeed> {
  outputs: Vec<OutputFor<S>>,
  forwards: Vec<OutputFor<S>>,
  returns: Vec<Return<S>>,
}

/// The object responsible for accumulating outputs and planning new transactions.
pub trait Scheduler<S: ScannerFeed>: Send {
  /// Accumulate outputs into the scheduler, yielding the Eventualities now to be scanned for.
  ///
  /// The `Vec<u8>` used as the key in the returned HashMap should be the encoded key the
  /// Eventualities are for.
  fn update(
    &mut self,
    txn: &mut impl DbTxn,
    update: SchedulerUpdate<S>,
  ) -> HashMap<Vec<u8>, Vec<EventualityFor<S>>>;
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
  pub fn acknowledge_block(
    &mut self,
    txn: &mut impl DbTxn,
    block_number: u64,
    key_to_activate: Option<KeyFor<S>>,
  ) {
    log::info!("acknowledging block {block_number}");
    assert!(
      ScannerDb::<S>::is_block_notable(txn, block_number),
      "acknowledging a block which wasn't notable"
    );
    ScannerDb::<S>::set_highest_acknowledged_block(txn, block_number);
    ScannerDb::<S>::queue_key(txn, block_number + S::WINDOW_LENGTH);
  }

  /// Queue Burns.
  ///
  /// The scanner only updates the scheduler with new outputs upon acknowledging a block. We can
  /// safely queue Burns so long as they're only actually added once we've handled the outputs from
  /// the block acknowledged prior to their queueing.
  pub fn queue_burns(&mut self, txn: &mut impl DbTxn, burns: Vec<()>) {
    let queue_as_of = ScannerDb::<S>::highest_acknowledged_block(txn)
      .expect("queueing Burns yet never acknowledged a block");
    todo!("TODO")
  }
}

/*
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
*/
