use core::marker::PhantomData;
use std::io;

use scale::Encode;
use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::{Get, DbTxn, create_db, db_channel};

use serai_in_instructions_primitives::InInstructionWithBalance;

use primitives::{ReceivedOutput, BorshG};

use crate::{lifetime::LifetimeStage, ScannerFeed, KeyFor, AddressFor, OutputFor, Return};

// The DB macro doesn't support `BorshSerialize + BorshDeserialize` as a bound, hence this.
trait Borshy: BorshSerialize + BorshDeserialize {}
impl<T: BorshSerialize + BorshDeserialize> Borshy for T {}

#[derive(BorshSerialize, BorshDeserialize)]
struct SeraiKeyDbEntry<K: Borshy> {
  activation_block_number: u64,
  key: K,
}

pub(crate) struct SeraiKey<K> {
  pub(crate) key: K,
  pub(crate) stage: LifetimeStage,
  pub(crate) block_at_which_reporting_starts: u64,
}

pub(crate) struct OutputWithInInstruction<S: ScannerFeed> {
  pub(crate) output: OutputFor<S>,
  pub(crate) return_address: Option<AddressFor<S>>,
  pub(crate) in_instruction: InInstructionWithBalance,
}

impl<S: ScannerFeed> OutputWithInInstruction<S> {
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    self.output.write(writer)?;
    // TODO self.return_address.write(writer)?;
    self.in_instruction.encode_to(writer);
    Ok(())
  }
}

create_db!(
  Scanner {
    ActiveKeys: <K: Borshy>() -> Vec<SeraiKeyDbEntry<K>>,

    // The next block to scan for received outputs
    NextToScanForOutputsBlock: () -> u64,
    // The next block to check for resolving eventualities
    NextToCheckForEventualitiesBlock: () -> u64,
    // The next block to potentially report
    NextToPotentiallyReportBlock: () -> u64,
    // Highest acknowledged block
    HighestAcknowledgedBlock: () -> u64,

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

    SerializedQueuedOutputs: (block_number: u64) -> Vec<u8>,
    SerializedOutputs: (block_number: u64) -> Vec<u8>,
  }
);

pub(crate) struct ScannerDb<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> ScannerDb<S> {
  /// Queue a key.
  ///
  /// Keys may be queued whenever, so long as they're scheduled to activate `WINDOW_LENGTH` blocks
  /// after the next block acknowledged after they've been set. There is no requirement that any
  /// prior keys have had their processing completed (meaning what should be a length-2 vector may
  /// be a length-n vector).
  ///
  /// A new key MUST NOT be queued to activate a block preceding the finishing of the key prior to
  /// its prior. There MUST only be two keys active at one time.
  ///
  /// activation_block_number is inclusive, so the key will be scanned for starting at the
  /// specified block.
  pub(crate) fn queue_key(txn: &mut impl DbTxn, activation_block_number: u64, key: KeyFor<S>) {
    // Set this block as notable
    NotableBlock::set(txn, activation_block_number, &());

    // TODO: Panic if we've ever seen this key before

    // Push the key
    let mut keys: Vec<SeraiKeyDbEntry<BorshG<KeyFor<S>>>> = ActiveKeys::get(txn).unwrap_or(vec![]);
    keys.push(SeraiKeyDbEntry { activation_block_number, key: BorshG(key) });
    ActiveKeys::set(txn, &keys);
  }
  /// Retire a key.
  ///
  /// The key retired must be the oldest key. There must be another key actively tracked.
  // TODO: This will be called from the Eventuality task yet this field is read by the scan task
  // We need to write the argument for its safety
  pub(crate) fn retire_key(txn: &mut impl DbTxn, key: KeyFor<S>) {
    let mut keys: Vec<SeraiKeyDbEntry<BorshG<KeyFor<S>>>> =
      ActiveKeys::get(txn).expect("retiring key yet no active keys");

    assert!(keys.len() > 1, "retiring our only key");
    assert_eq!(keys[0].key.0, key, "not retiring the oldest key");
    keys.remove(0);
    ActiveKeys::set(txn, &keys);
  }
  /// Fetch the active keys, as of the next-to-scan-for-outputs Block.
  ///
  /// This means the scan task should scan for all keys returned by this.
  pub(crate) fn active_keys_as_of_next_to_scan_for_outputs_block(
    getter: &impl Get,
  ) -> Option<Vec<SeraiKey<KeyFor<S>>>> {
    // We don't take this as an argument as we don't keep all historical keys in memory
    // If we've scanned block 1,000,000, we can't answer the active keys as of block 0
    let block_number = Self::next_to_scan_for_outputs_block(getter)?;

    let raw_keys: Vec<SeraiKeyDbEntry<BorshG<KeyFor<S>>>> = ActiveKeys::get(getter)?;
    let mut keys = Vec::with_capacity(2);
    for i in 0 .. raw_keys.len() {
      if block_number < raw_keys[i].activation_block_number {
        continue;
      }
      let (stage, block_at_which_reporting_starts) =
        LifetimeStage::calculate_stage_and_reporting_start_block::<S>(
          block_number,
          raw_keys[i].activation_block_number,
          raw_keys.get(i + 1).map(|key| key.activation_block_number),
        );
      keys.push(SeraiKey { key: raw_keys[i].key.0, stage, block_at_which_reporting_starts });
    }
    assert!(keys.len() <= 2, "more than two keys active");
    Some(keys)
  }

  pub(crate) fn set_start_block(txn: &mut impl DbTxn, start_block: u64, id: [u8; 32]) {
    assert!(
      NextToScanForOutputsBlock::get(txn).is_none(),
      "setting start block but prior set start block"
    );

    NextToScanForOutputsBlock::set(txn, &start_block);
    // We can receive outputs in this block, but any descending transactions will be in the next
    // block. This, with the check on-set, creates a bound that this value in the DB is non-zero.
    NextToCheckForEventualitiesBlock::set(txn, &(start_block + 1));
    NextToPotentiallyReportBlock::set(txn, &start_block);
  }

  pub(crate) fn latest_scannable_block(getter: &impl Get) -> Option<u64> {
    // We can only scan up to whatever block we've checked the Eventualities of, plus the window
    // length. Since this returns an inclusive bound, we need to subtract 1
    // See `eventuality.rs` for more info
    NextToCheckForEventualitiesBlock::get(getter).map(|b| b + S::WINDOW_LENGTH - 1)
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
    assert!(
      next_to_check_for_eventualities_block != 0,
      "next to check for eventualities block was 0 when it's bound non-zero"
    );
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

  pub(crate) fn set_highest_acknowledged_block(
    txn: &mut impl DbTxn,
    highest_acknowledged_block: u64,
  ) {
    HighestAcknowledgedBlock::set(txn, &highest_acknowledged_block);
  }
  pub(crate) fn highest_acknowledged_block(getter: &impl Get) -> Option<u64> {
    HighestAcknowledgedBlock::get(getter)
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

  pub(crate) fn flag_notable(txn: &mut impl DbTxn, block_number: u64) {
    assert!(
      NextToPotentiallyReportBlock::get(txn).unwrap() <= block_number,
      "already potentially reported a block we're only now flagging as notable"
    );
    NotableBlock::set(txn, block_number, &());
  }

  pub(crate) fn is_block_notable(getter: &impl Get, number: u64) -> bool {
    NotableBlock::get(getter, number).is_some()
  }

  pub(crate) fn acquire_batch_id(txn: &mut impl DbTxn) -> u32 {
    todo!("TODO")
  }

  pub(crate) fn return_address_and_in_instruction_for_forwarded_output(
    getter: &impl Get,
    output: &<OutputFor<S> as ReceivedOutput<KeyFor<S>, AddressFor<S>>>::Id,
  ) -> Option<(Option<AddressFor<S>>, InInstructionWithBalance)> {
    todo!("TODO")
  }
}

/// The data produced by scanning a block.
///
/// This is the sender's version which includes the forwarded outputs with their InInstructions,
/// which need to be saved to the database for later retrieval.
pub(crate) struct SenderScanData<S: ScannerFeed> {
  /// The block number.
  pub(crate) block_number: u64,
  /// The received outputs which should be accumulated into the scheduler.
  pub(crate) received_external_outputs: Vec<OutputFor<S>>,
  /// The outputs which need to be forwarded.
  pub(crate) forwards: Vec<OutputWithInInstruction<S>>,
  /// The outputs which need to be returned.
  pub(crate) returns: Vec<Return<S>>,
}

/// The data produced by scanning a block.
///
/// This is the receiver's version which doesn't include the forwarded outputs' InInstructions, as
/// the Eventuality task doesn't need it to process this block.
pub(crate) struct ReceiverScanData<S: ScannerFeed> {
  /// The block number.
  pub(crate) block_number: u64,
  /// The received outputs which should be accumulated into the scheduler.
  pub(crate) received_external_outputs: Vec<OutputFor<S>>,
  /// The outputs which need to be forwarded.
  pub(crate) forwards: Vec<OutputFor<S>>,
  /// The outputs which need to be returned.
  pub(crate) returns: Vec<Return<S>>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub(crate) struct SerializedScanData {
  pub(crate) block_number: u64,
  pub(crate) data: Vec<u8>,
}

db_channel! {
  ScannerScanEventuality {
    ScannedBlock: (empty_key: ()) -> SerializedScanData,
  }
}

pub(crate) struct ScanToEventualityDb<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> ScanToEventualityDb<S> {
  pub(crate) fn send_scan_data(txn: &mut impl DbTxn, block_number: u64, data: &SenderScanData<S>) {
    /*
    SerializedForwardedOutputsIndex: (block_number: u64) -> Vec<u8>,
    SerializedForwardedOutput: (output_id: &[u8]) -> Vec<u8>,

    pub(crate) fn save_output_being_forwarded(
      txn: &mut impl DbTxn,
      block_forwarded_from: u64,
      output: &OutputWithInInstruction<S>,
    ) {
      let mut buf = Vec::with_capacity(128);
      output.write(&mut buf).unwrap();

      let id = output.output.id();

      // Save this to an index so we can later fetch all outputs to forward
      let mut forwarded_outputs = SerializedForwardedOutputsIndex::get(txn, block_forwarded_from)
        .unwrap_or(Vec::with_capacity(32));
      forwarded_outputs.extend(id.as_ref());
      SerializedForwardedOutputsIndex::set(txn, block_forwarded_from, &forwarded_outputs);

      // Save the output itself
      SerializedForwardedOutput::set(txn, id.as_ref(), &buf);
    }
    */

    ScannedBlock::send(txn, (), todo!("TODO"));
  }
  pub(crate) fn recv_scan_data(txn: &mut impl DbTxn, block_number: u64) -> ReceiverScanData<S> {
    let data =
      ScannedBlock::try_recv(txn, ()).expect("receiving data for a scanned block not yet sent");
    assert_eq!(
      block_number, data.block_number,
      "received data for a scanned block distinct than expected"
    );
    let data = &data.data;

    todo!("TODO")
  }
}

#[derive(BorshSerialize, BorshDeserialize)]
pub(crate) struct BlockBoundInInstructions {
  pub(crate) block_number: u64,
  pub(crate) in_instructions: Vec<InInstructionWithBalance>,
}

db_channel! {
  ScannerScanReport {
    InInstructions: (empty_key: ()) -> BlockBoundInInstructions,
  }
}

pub(crate) struct ScanToReportDb<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> ScanToReportDb<S> {
  pub(crate) fn send_in_instructions(
    txn: &mut impl DbTxn,
    block_number: u64,
    in_instructions: Vec<InInstructionWithBalance>,
  ) {
    if !in_instructions.is_empty() {
      // Set this block as notable
      NotableBlock::set(txn, block_number, &());
    }

    InInstructions::send(txn, (), &BlockBoundInInstructions { block_number, in_instructions });
  }

  pub(crate) fn recv_in_instructions(
    txn: &mut impl DbTxn,
    block_number: u64,
  ) -> Vec<InInstructionWithBalance> {
    let data = InInstructions::try_recv(txn, ())
      .expect("receiving InInstructions for a scanned block not yet sent");
    assert_eq!(
      block_number, data.block_number,
      "received InInstructions for a scanned block distinct than expected"
    );
    data.in_instructions
  }
}
