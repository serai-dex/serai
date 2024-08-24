use core::marker::PhantomData;

use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::{Get, DbTxn, create_db};

use primitives::{Id, ReceivedOutput, Block, BorshG};

use crate::{lifetime::LifetimeStage, ScannerFeed, BlockIdFor, KeyFor, OutputFor};

// The DB macro doesn't support `BorshSerialize + BorshDeserialize` as a bound, hence this.
trait Borshy: BorshSerialize + BorshDeserialize {}
impl<T: BorshSerialize + BorshDeserialize> Borshy for T {}

#[derive(BorshSerialize, BorshDeserialize)]
struct SeraiKeyDbEntry<K: Borshy> {
  activation_block_number: u64,
  key: K,
}

pub(crate) struct SeraiKey<K> {
  pub(crate) stage: LifetimeStage,
  pub(crate) key: K,
}

pub(crate) struct OutputWithInInstruction<K: GroupEncoding, A, O: ReceivedOutput<K, A>> {
  output: O,
  refund_address: A,
  in_instruction: InInstructionWithBalance,
}

impl<K: GroupEncoding, A, O: ReceivedOutput<K, A>> OutputWithInInstruction<K, A, O> {
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    self.output.write(writer)?;
    // TODO self.refund_address.write(writer)?;
    self.in_instruction.encode_to(writer);
    Ok(())
  }
}

create_db!(
  Scanner {
    BlockId: <I: Id>(number: u64) -> I,
    BlockNumber: <I: Id>(id: I) -> u64,

    ActiveKeys: <K: Borshy>() -> Vec<SeraiKeyDbEntry<K>>,

    // The latest finalized block to appear of a blockchain
    LatestFinalizedBlock: () -> u64,
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
    let mut keys: Vec<SeraiKeyDbEntry<BorshG<KeyFor<S>>>> = ActiveKeys::get(txn).unwrap_or(vec![]);
    for key_i in &keys {
      if key == key_i.key.0 {
        panic!("queueing a key prior queued");
      }
    }
    keys.push(SeraiKeyDbEntry { activation_block_number, key: BorshG(key) });
    ActiveKeys::set(txn, &keys);
  }
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
      keys.push(SeraiKey {
        key: raw_keys[i].key.0,
        stage: LifetimeStage::calculate::<S>(
          block_number,
          raw_keys[i].activation_block_number,
          raw_keys.get(i + 1).map(|key| key.activation_block_number),
        ),
      });
    }
    assert!(keys.len() <= 2);
    Some(keys)
  }

  pub(crate) fn set_start_block(txn: &mut impl DbTxn, start_block: u64, id: BlockIdFor<S>) {
    assert!(
      LatestFinalizedBlock::get(txn).is_none(),
      "setting start block but prior set start block"
    );

    Self::set_block(txn, start_block, id);

    LatestFinalizedBlock::set(txn, &start_block);
    NextToScanForOutputsBlock::set(txn, &start_block);
    // We can receive outputs in this block, but any descending transactions will be in the next
    // block. This, with the check on-set, creates a bound that this value in the DB is non-zero.
    NextToCheckForEventualitiesBlock::set(txn, &(start_block + 1));
    NextToPotentiallyReportBlock::set(txn, &start_block);
  }

  pub(crate) fn set_latest_finalized_block(txn: &mut impl DbTxn, latest_finalized_block: u64) {
    LatestFinalizedBlock::set(txn, &latest_finalized_block);
  }
  pub(crate) fn latest_finalized_block(getter: &impl Get) -> Option<u64> {
    LatestFinalizedBlock::get(getter)
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

  pub(crate) fn set_in_instructions(txn: &mut impl DbTxn, block_number: u64, outputs: Vec<OutputWithInInstruction<KeyFor<S>, AddressFor<S>, OutputFor<S>>>) {
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
