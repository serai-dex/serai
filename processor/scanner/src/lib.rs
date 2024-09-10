#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{marker::PhantomData, fmt::Debug};
use std::{io, collections::HashMap};

use group::GroupEncoding;

use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::{Get, DbTxn, Db};

use serai_primitives::{NetworkId, Coin, Amount};
use serai_coins_primitives::OutInstructionWithBalance;

use primitives::{task::*, Address, ReceivedOutput, Block, Payment};

// Logic for deciding where in its lifetime a multisig is.
mod lifetime;
pub use lifetime::LifetimeStage;

// Database schema definition and associated functions.
mod db;
use db::ScannerGlobalDb;
pub use db::{Batches, BatchesToSign, AcknowledgedBatches, CompletedEventualities};
// Task to index the blockchain, ensuring we don't reorganize finalized blocks.
mod index;
// Scans blocks for received coins.
mod scan;
/// Task which reports Batches to Substrate.
mod report;
/// Task which handles events from Substrate once we can.
mod substrate;
/// Check blocks for transactions expected to eventually occur.
mod eventuality;

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
pub trait ScannerFeed: 'static + Send + Sync + Clone {
  /// The ID of the network being scanned for.
  const NETWORK: NetworkId;

  /// The amount of confirmations a block must have to be considered finalized.
  ///
  /// This value must be at least `1`.
  const CONFIRMATIONS: u64;

  /// The amount of blocks to process in parallel.
  ///
  /// This must be at least `1`. This value should be the worst-case latency to handle a block
  /// divided by the expected block time.
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
  /// resolve without manual intervention/changing the arguments.
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

  /// The dust threshold for the specified coin.
  ///
  /// This MUST be constant. Serai MUST NOT create internal outputs worth less than this. This
  /// SHOULD be a value worth handling at a human level.
  fn dust(coin: Coin) -> Amount;

  /// The cost to aggregate an input as of the specified block.
  ///
  /// This is defined as the transaction fee for a 2-input, 1-output transaction.
  async fn cost_to_aggregate(
    &self,
    coin: Coin,
    reference_block: &Self::Block,
  ) -> Result<Amount, Self::EphemeralError>;
}

/// The key type for this ScannerFeed.
pub type KeyFor<S> = <<S as ScannerFeed>::Block as Block>::Key;
/// The address type for this ScannerFeed.
pub type AddressFor<S> = <<S as ScannerFeed>::Block as Block>::Address;
/// The output type for this ScannerFeed.
pub type OutputFor<S> = <<S as ScannerFeed>::Block as Block>::Output;
/// The eventuality type for this ScannerFeed.
pub type EventualityFor<S> = <<S as ScannerFeed>::Block as Block>::Eventuality;
/// The block type for this ScannerFeed.
pub type BlockFor<S> = <S as ScannerFeed>::Block;

/// A return to occur.
pub struct Return<S: ScannerFeed> {
  address: AddressFor<S>,
  output: OutputFor<S>,
}

impl<S: ScannerFeed> Return<S> {
  pub(crate) fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    self.address.serialize(writer)?;
    self.output.write(writer)
  }

  pub(crate) fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let address = AddressFor::<S>::deserialize_reader(reader)?;
    let output = OutputFor::<S>::read(reader)?;
    Ok(Return { address, output })
  }

  /// The address to return the output to.
  pub fn address(&self) -> &AddressFor<S> {
    &self.address
  }

  /// The output to return.
  pub fn output(&self) -> &OutputFor<S> {
    &self.output
  }
}

/// An update for the scheduler.
pub struct SchedulerUpdate<S: ScannerFeed> {
  outputs: Vec<OutputFor<S>>,
  forwards: Vec<OutputFor<S>>,
  returns: Vec<Return<S>>,
}

impl<S: ScannerFeed> SchedulerUpdate<S> {
  /// The outputs to accumulate.
  ///
  /// These MUST be accumulated.
  pub fn outputs(&self) -> &[OutputFor<S>] {
    &self.outputs
  }

  /// The outputs to forward to the latest multisig.
  ///
  /// These MUST be forwarded in a 1-input 1-output transaction or dropped (if the fees are too
  /// high to make the forwarding transaction).
  pub fn forwards(&self) -> &[OutputFor<S>] {
    &self.forwards
  }

  /// The outputs to return.
  ///
  /// These SHOULD be returned as specified (potentially in batch). They MAY be dropped if the fees
  /// are too high to make the return transaction.
  pub fn returns(&self) -> &[Return<S>] {
    &self.returns
  }
}

/// The object responsible for accumulating outputs and planning new transactions.
pub trait Scheduler<S: ScannerFeed>: 'static + Send {
  /// The type for a signable transaction.
  type SignableTransaction: scheduler_primitives::SignableTransaction;

  /// Activate a key.
  ///
  /// This SHOULD setup any necessary database structures. This SHOULD NOT cause the new key to
  /// be used as the primary key. The multisig rotation time clearly establishes its steps.
  fn activate_key(txn: &mut impl DbTxn, key: KeyFor<S>);

  /// Flush all outputs within a retiring key to the new key.
  ///
  /// When a key is activated, the existing multisig should retain its outputs and utility for a
  /// certain time period. With `flush_key`, all outputs should be directed towards fulfilling some
  /// obligation or the `new_key`. Every output held by the retiring key MUST be connected to an
  /// Eventuality. If a key no longer has active Eventualities, it MUST be able to be retired
  /// without losing any coins.
  ///
  /// If the retiring key has any unfulfilled payments associated with it, those MUST be made
  /// the responsibility of the new key.
  fn flush_key(
    txn: &mut impl DbTxn,
    block: &BlockFor<S>,
    retiring_key: KeyFor<S>,
    new_key: KeyFor<S>,
  ) -> HashMap<Vec<u8>, Vec<EventualityFor<S>>>;

  /// Retire a key as it'll no longer be used.
  ///
  /// Any key retired MUST NOT still have outputs associated with it. This SHOULD be a NOP other
  /// than any assertions and database cleanup. This MUST NOT be expected to be called in a fashion
  /// ordered to any other calls.
  fn retire_key(txn: &mut impl DbTxn, key: KeyFor<S>);

  /// Accumulate outputs into the scheduler, yielding the Eventualities now to be scanned for.
  ///
  /// `active_keys` is the list of active keys, potentially including a key for which we've already
  /// called `retire_key` on. If so, its stage will be `Finishing` and no further operations will
  /// be expected for it. Nonetheless, it may be present.
  ///
  /// The `Vec<u8>` used as the key in the returned HashMap should be the encoded key the
  /// Eventualities are for.
  fn update(
    txn: &mut impl DbTxn,
    block: &BlockFor<S>,
    active_keys: &[(KeyFor<S>, LifetimeStage)],
    update: SchedulerUpdate<S>,
  ) -> HashMap<Vec<u8>, Vec<EventualityFor<S>>>;

  /// Fulfill a series of payments, yielding the Eventualities now to be scanned for.
  ///
  /// Any Eventualities returned by this function must include an output-to-Serai (such as a Branch
  /// or Change), unless they descend from a transaction returned by this function which satisfies
  /// that requirement.
  ///
  /// `active_keys` is the list of active keys, potentially including a key for which we've already
  /// called `retire_key` on. If so, its stage will be `Finishing` and no further operations will
  /// be expected for it. Nonetheless, it may be present.
  ///
  /// The `Vec<u8>` used as the key in the returned HashMap should be the encoded key the
  /// Eventualities are for.
  /*
    We need an output-to-Serai so we can detect a block with an Eventuality completion with regards
    to Burns, forcing us to ensure we have accumulated all the Burns we should by the time we
    handle that block. We explicitly don't require children have this requirement as by detecting
    the first resolution, we ensure we'll accumulate the Burns (therefore becoming aware of the
    childrens' Eventualities, enabling recognizing their resolutions).

    This carve out enables the following:

      ------------------  Fulfillment TX  ----------------------
      | Primary Output | ---------------> | New Primary Output |
      ------------------         |        ----------------------
                                 |
                                 |        ------------------------------
                                 |------> | Branching Output for Burns |
                                          ------------------------------

    Without wasting pointless Change outputs on every transaction (as there's a single parent which
    has an output-to-Serai, the new primary output).
  */
  fn fulfill(
    txn: &mut impl DbTxn,
    block: &BlockFor<S>,
    active_keys: &[(KeyFor<S>, LifetimeStage)],
    payments: Vec<Payment<AddressFor<S>>>,
  ) -> HashMap<Vec<u8>, Vec<EventualityFor<S>>>;
}

/// A representation of a scanner.
#[allow(non_snake_case)]
pub struct Scanner<S: ScannerFeed> {
  substrate_handle: TaskHandle,
  _S: PhantomData<S>,
}
impl<S: ScannerFeed> Scanner<S> {
  /// Create a new scanner.
  ///
  /// This will begin its execution, spawning several asynchronous tasks.
  pub async fn new<Sch: Scheduler<S>>(
    mut db: impl Db,
    feed: S,
    start_block: u64,
    start_key: KeyFor<S>,
  ) -> Self {
    if !ScannerGlobalDb::<S>::has_any_key_been_queued(&db) {
      let mut txn = db.txn();
      ScannerGlobalDb::<S>::queue_key(&mut txn, start_block, start_key);
      txn.commit();
    }

    let index_task = index::IndexTask::new(db.clone(), feed.clone(), start_block).await;
    let scan_task = scan::ScanTask::new(db.clone(), feed.clone(), start_block);
    let report_task = report::ReportTask::<_, S>::new(db.clone(), start_block);
    let substrate_task = substrate::SubstrateTask::<_, S>::new(db.clone());
    let eventuality_task = eventuality::EventualityTask::<_, _, Sch>::new(db, feed, start_block);

    let (index_task_def, _index_handle) = Task::new();
    let (scan_task_def, scan_handle) = Task::new();
    let (report_task_def, report_handle) = Task::new();
    let (substrate_task_def, substrate_handle) = Task::new();
    let (eventuality_task_def, eventuality_handle) = Task::new();

    // Upon indexing a new block, scan it
    tokio::spawn(index_task.continually_run(index_task_def, vec![scan_handle.clone()]));
    // Upon scanning a block, report it
    tokio::spawn(scan_task.continually_run(scan_task_def, vec![report_handle]));
    // Upon reporting a block, we do nothing (as the burden is on Substrate which won't be
    // immediately ready)
    tokio::spawn(report_task.continually_run(report_task_def, vec![]));
    // Upon handling an event from Substrate, we run the Eventuality task (as it's what's affected)
    tokio::spawn(substrate_task.continually_run(substrate_task_def, vec![eventuality_handle]));
    // Upon handling the Eventualities in a block, we run the scan task as we've advanced the
    // window its allowed to scan
    tokio::spawn(eventuality_task.continually_run(eventuality_task_def, vec![scan_handle]));

    Self { substrate_handle, _S: PhantomData }
  }

  /// Acknowledge a Batch having been published on Serai.
  ///
  /// This means the specified Batch was ordered on Serai in relation to Burn events, and all
  /// validators have achieved synchrony on it.
  ///
  /// `in_instruction_succeededs` is the result of executing each InInstruction within this batch,
  /// true if it succeeded and false if it did not (and did not cause any state changes on Serai).
  ///
  /// `burns` is a list of Burns to queue with the acknowledgement of this Batch for efficiency's
  /// sake. Any Burns passed here MUST NOT be passed into any other call of `acknowledge_batch` nor
  /// `queue_burns`. Doing so will cause them to be executed multiple times.
  ///
  /// The calls to this function must be ordered with regards to `queue_burns`.
  pub fn acknowledge_batch(
    &mut self,
    mut txn: impl DbTxn,
    batch_id: u32,
    in_instruction_succeededs: Vec<bool>,
    burns: Vec<OutInstructionWithBalance>,
    key_to_activate: Option<KeyFor<S>>,
  ) {
    log::info!("acknowledging batch {batch_id}");

    // Queue acknowledging this block via the Substrate task
    substrate::queue_acknowledge_batch::<S>(
      &mut txn,
      batch_id,
      in_instruction_succeededs,
      burns,
      key_to_activate,
    );
    // Commit this txn so this data is flushed
    txn.commit();
    // Then run the Substrate task
    self.substrate_handle.run_now();
  }

  /// Queue Burns.
  ///
  /// The scanner only updates the scheduler with new outputs upon acknowledging a block. The
  /// ability to fulfill Burns, and therefore their order, is dependent on the current output
  /// state. This immediately sets a bound that this function is ordered with regards to
  /// `acknowledge_batch`.
  ///
  /// The Burns specified here MUST NOT also be passed to `acknowledge_batch`.
  /*
    The fact Burns can be queued during any Substrate block is problematic. The scanner is allowed
    to scan anything within the window set by the Eventuality task. The Eventuality task is allowed
    to handle all blocks until it reaches a block needing acknowledgement.

    This means we may queue Burns when the latest acknowledged block is 1, yet we've already
    scanned 101. Such Burns may complete back in block 2, and we simply wouldn't have noticed due
    to not having yet generated the Eventualities.

    We solve this by mandating all transactions made as the result of an Eventuality include a
    output-to-Serai worth at least `DUST`. If that occurs, the scanner will force a consensus
    protocol on block 2. Accordingly, we won't scan all the way to block 101 (missing the
    resolution of the Eventuality) as we'll obtain synchrony on block 2 and all Burns queued prior
    to it.

    Another option would be to re-check historical blocks, yet this would potentially redo an
    unbounded amount of work. It would also not allow us to safely detect if received outputs were
    in fact the result of Eventualities or not.

    Another option would be to schedule Burns after the next-acknowledged block, yet this would add
    latency and likely practically require we add regularly scheduled notable blocks (which may be
    unnecessary).
  */
  pub fn queue_burns(&mut self, mut txn: impl DbTxn, burns: Vec<OutInstructionWithBalance>) {
    if burns.is_empty() {
      return;
    }

    // Queue queueing these burns via the Substrate task
    substrate::queue_queue_burns::<S>(&mut txn, burns);
    // Commit this txn so this data is flushed
    txn.commit();
    // Then run the Substrate task
    self.substrate_handle.run_now();
  }
}
