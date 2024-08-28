use core::marker::PhantomData;
use std::io;

use scale::Encode;
use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::{Get, DbTxn, create_db};

use serai_in_instructions_primitives::InInstructionWithBalance;

use primitives::{EncodableG, ReceivedOutput, EventualityTracker};

use crate::{
  lifetime::LifetimeStage, db::OutputWithInInstruction, ScannerFeed, KeyFor, AddressFor, OutputFor,
  EventualityFor, Return, scan::next_to_scan_for_outputs_block,
};

// The DB macro doesn't support `BorshSerialize + BorshDeserialize` as a bound, hence this.
trait Borshy: BorshSerialize + BorshDeserialize {}
impl<T: BorshSerialize + BorshDeserialize> Borshy for T {}

create_db!(
  ScannerScan {
    // The next block to scan for received outputs
    NextToScanForOutputsBlock: () -> u64,

    SerializedQueuedOutputs: (block_number: u64) -> Vec<u8>,
  }
);

pub(crate) struct ScanDb<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> ScanDb<S> {
  pub(crate) fn set_next_to_scan_for_outputs_block(
    txn: &mut impl DbTxn,
    next_to_scan_for_outputs_block: u64,
  ) {
    NextToScanForOutputsBlock::set(txn, &next_to_scan_for_outputs_block);
  }
  pub(crate) fn next_to_scan_for_outputs_block(getter: &impl Get) -> Option<u64> {
    NextToScanForOutputsBlock::get(getter)
  }

  pub(crate) fn take_queued_outputs(
    txn: &mut impl DbTxn,
    block_number: u64,
  ) -> Vec<OutputWithInInstruction<S>> {
    todo!("TODO")
  }

  pub(crate) fn queue_output_until_block(
    txn: &mut impl DbTxn,
    queue_for_block: u64,
    output: &OutputWithInInstruction<S>,
  ) {
    let mut outputs =
      SerializedQueuedOutputs::get(txn, queue_for_block).unwrap_or(Vec::with_capacity(128));
    output.write(&mut outputs).unwrap();
    SerializedQueuedOutputs::set(txn, queue_for_block, &outputs);
  }
}
