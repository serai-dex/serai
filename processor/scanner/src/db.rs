use core::marker::PhantomData;

use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::{Get, DbTxn, create_db};

use primitives::{Id, ReceivedOutput, Block, BorshG};

use crate::{ScannerFeed, BlockIdFor, KeyFor, OutputFor};

// The DB macro doesn't support `BorshSerialize + BorshDeserialize` as a bound, hence this.
trait Borshy: BorshSerialize + BorshDeserialize {}
impl<T: BorshSerialize + BorshDeserialize> Borshy for T {}

#[derive(BorshSerialize, BorshDeserialize)]
pub(crate) struct SeraiKey<K: Borshy> {
  pub(crate) activation_block_number: u64,
  pub(crate) retirement_block_number: Option<u64>,
  pub(crate) key: K,
}

create_db!(
  Scanner {
    BlockId: <I: Id>(number: u64) -> I,
    BlockNumber: <I: Id>(id: I) -> u64,

    ActiveKeys: <K: Borshy>() -> Vec<SeraiKey<K>>,

    // The latest finalized block to appear of a blockchain
    LatestFinalizedBlock: () -> u64,
    // The next block to scan for received outputs
    NextToScanForOutputsBlock: () -> u64,
    // The next block to check for resolving eventualities
    NextToCheckForEventualitiesBlock: () -> u64,
    // The next block to potentially report
    NextToPotentiallyReportBlock: () -> u64,

    // If a block was notable
    /*
      A block is notable if one of three conditions are met:

      1) We activated a key within this block.
      2) We retired a key within this block.
      3) We received outputs within this block.

      The first two conditions, and the reasoning for them, is extensively documented in
      `spec/processor/Multisig Rotation.md`. The third is obvious (as any block we receive outputs
      in needs synchrony so that we can spend the received outputs).

      We save if a block is notable here by either the scan for received outputs task or the
      check for eventuality completion task. Once a block has been processed by both, the reporting
      task will report any notable blocks. Finally, the task which sets the block safe to scan to
      makes its decision based on the notable blocks and the acknowledged blocks.
    */
    // This collapses from `bool` to `()`, using if the value was set for true and false otherwise
    NotableBlock: (number: u64) -> (),

    SerializedOutputs: (block_number: u64) -> Vec<u8>,
  }
);

pub(crate) struct ScannerDb<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> ScannerDb<S> {
  pub(crate) fn set_block(txn: &mut impl DbTxn, number: u64, id: BlockIdFor<S>) {
    BlockId::set(txn, number, &id);
    BlockNumber::set(txn, id, &number);
  }
  pub(crate) fn block_id(getter: &impl Get, number: u64) -> Option<BlockIdFor<S>> {
    BlockId::get(getter, number)
  }
  pub(crate) fn block_number(getter: &impl Get, id: BlockIdFor<S>) -> Option<u64> {
    BlockNumber::get(getter, id)
  }

  // activation_block_number is inclusive, so the key will be scanned for starting at the specified
  // block
  pub(crate) fn queue_key(txn: &mut impl DbTxn, activation_block_number: u64, key: KeyFor<S>) {
    // Set this block as notable
    NotableBlock::set(txn, activation_block_number, &());

    // Push the key
    let mut keys: Vec<SeraiKey<BorshG<KeyFor<S>>>> = ActiveKeys::get(txn).unwrap_or(vec![]);
    for key_i in &keys {
      if key == key_i.key.0 {
        panic!("queueing a key prior queued");
      }
    }
    keys.push(SeraiKey {
      activation_block_number,
      retirement_block_number: None,
      key: BorshG(key),
    });
    ActiveKeys::set(txn, &keys);
  }
  // retirement_block_number is inclusive, so the key will no longer be scanned for as of the
  // specified block
  pub(crate) fn retire_key(txn: &mut impl DbTxn, retirement_block_number: u64, key: KeyFor<S>) {
    let mut keys: Vec<SeraiKey<BorshG<KeyFor<S>>>> =
      ActiveKeys::get(txn).expect("retiring key yet no active keys");

    assert!(keys.len() > 1, "retiring our only key");
    for i in 0 .. keys.len() {
      if key == keys[i].key.0 {
        keys[i].retirement_block_number = Some(retirement_block_number);
        ActiveKeys::set(txn, &keys);
        return;
      }

      // This is not the key in question, but since it's older, it already should've been queued
      // for retirement
      assert!(
        keys[i].retirement_block_number.is_some(),
        "older key wasn't retired before newer key"
      );
    }
    panic!("retiring key yet not present in keys")
  }
  pub(crate) fn keys(getter: &impl Get) -> Option<Vec<SeraiKey<BorshG<KeyFor<S>>>>> {
    ActiveKeys::get(getter)
  }

  pub(crate) fn set_start_block(txn: &mut impl DbTxn, start_block: u64, id: BlockIdFor<S>) {
    Self::set_block(txn, start_block, id);
    LatestFinalizedBlock::set(txn, &start_block);
    NextToScanForOutputsBlock::set(txn, &start_block);
    NextToCheckForEventualitiesBlock::set(txn, &start_block);
    NextToPotentiallyReportBlock::set(txn, &start_block);
  }

  pub(crate) fn set_latest_finalized_block(txn: &mut impl DbTxn, latest_finalized_block: u64) {
    LatestFinalizedBlock::set(txn, &latest_finalized_block);
  }
  pub(crate) fn latest_finalized_block(getter: &impl Get) -> Option<u64> {
    LatestFinalizedBlock::get(getter)
  }

  pub(crate) fn latest_scannable_block(getter: &impl Get) -> Option<u64> {
    // This is whatever block we've checked the Eventualities of, plus the window length
    // See `eventuality.rs` for more info
    NextToCheckForEventualitiesBlock::get(getter).map(|b| b + S::WINDOW_LENGTH)
  }

  pub(crate) fn set_next_to_scan_for_outputs_block(
    txn: &mut impl DbTxn,
    next_to_scan_for_outputs_block: u64,
  ) {
    NextToScanForOutputsBlock::set(txn, &next_to_scan_for_outputs_block);
  }
  pub(crate) fn next_to_scan_for_outputs_block(getter: &impl Get) -> Option<u64> {
    NextToScanForOutputsBlock::get(getter)
  }

  pub(crate) fn set_next_to_check_for_eventualities_block(
    txn: &mut impl DbTxn,
    next_to_check_for_eventualities_block: u64,
  ) {
    NextToCheckForEventualitiesBlock::set(txn, &next_to_check_for_eventualities_block);
  }
  pub(crate) fn next_to_check_for_eventualities_block(getter: &impl Get) -> Option<u64> {
    NextToCheckForEventualitiesBlock::get(getter)
  }

  pub(crate) fn set_next_to_potentially_report_block(
    txn: &mut impl DbTxn,
    next_to_potentially_report_block: u64,
  ) {
    NextToPotentiallyReportBlock::set(txn, &next_to_potentially_report_block);
  }
  pub(crate) fn next_to_potentially_report_block(getter: &impl Get) -> Option<u64> {
    NextToPotentiallyReportBlock::get(getter)
  }

  pub(crate) fn set_outputs(txn: &mut impl DbTxn, block_number: u64, outputs: Vec<OutputFor<S>>) {
    if outputs.is_empty() {
      return;
    }

    // Set this block as notable
    NotableBlock::set(txn, block_number, &());

    let mut buf = Vec::with_capacity(outputs.len() * 128);
    for output in outputs {
      output.write(&mut buf).unwrap();
    }
    SerializedOutputs::set(txn, block_number, &buf);
  }

  pub(crate) fn is_block_notable(getter: &impl Get, number: u64) -> bool {
    NotableBlock::get(getter, number).is_some()
  }
}
