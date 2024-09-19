use core::marker::PhantomData;
use std::io::{self, Read, Write};

use group::GroupEncoding;

use scale::{Encode, Decode, IoReader};
use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::{Get, DbTxn, create_db, db_channel};

use serai_in_instructions_primitives::{InInstructionWithBalance, Batch};
use serai_coins_primitives::OutInstructionWithBalance;

use primitives::{EncodableG, ReceivedOutput};

use crate::{
  lifetime::{LifetimeStage, Lifetime},
  ScannerFeed, KeyFor, AddressFor, OutputFor, Return,
  scan::next_to_scan_for_outputs_block,
};

// The DB macro doesn't support `BorshSerialize + BorshDeserialize` as a bound, hence this.
trait Borshy: BorshSerialize + BorshDeserialize {}
impl<T: BorshSerialize + BorshDeserialize> Borshy for T {}

#[derive(BorshSerialize, BorshDeserialize)]
struct SeraiKeyDbEntry<K: Borshy> {
  activation_block_number: u64,
  key: K,
}

#[derive(Clone)]
pub(crate) struct SeraiKey<K> {
  pub(crate) key: K,
  pub(crate) stage: LifetimeStage,
  pub(crate) activation_block_number: u64,
  pub(crate) block_at_which_reporting_starts: u64,
  pub(crate) block_at_which_forwarding_starts: Option<u64>,
}

pub(crate) struct OutputWithInInstruction<S: ScannerFeed> {
  pub(crate) output: OutputFor<S>,
  pub(crate) return_address: Option<AddressFor<S>>,
  pub(crate) in_instruction: InInstructionWithBalance,
}

impl<S: ScannerFeed> OutputWithInInstruction<S> {
  pub(crate) fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let output = OutputFor::<S>::read(reader)?;
    let return_address = {
      let mut opt = [0xff];
      reader.read_exact(&mut opt)?;
      assert!((opt[0] == 0) || (opt[0] == 1));
      (opt[0] == 1).then(|| AddressFor::<S>::deserialize_reader(reader)).transpose()?
    };
    let in_instruction =
      InInstructionWithBalance::decode(&mut IoReader(reader)).map_err(io::Error::other)?;
    Ok(Self { output, return_address, in_instruction })
  }
  pub(crate) fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    self.output.write(writer)?;
    if let Some(return_address) = &self.return_address {
      writer.write_all(&[1])?;
      return_address.serialize(writer)?;
    } else {
      writer.write_all(&[0])?;
    }
    self.in_instruction.encode_to(writer);
    Ok(())
  }
}

create_db!(
  ScannerGlobal {
    StartBlock: () -> u64,

    QueuedKey: <K: Encode>(key: K) -> (),

    ActiveKeys: <K: Borshy>() -> Vec<SeraiKeyDbEntry<K>>,
    RetireAt: <K: Encode>(key: K) -> u64,

    // The next block to potentially report
    NextToPotentiallyReportBlock: () -> u64,
    // Highest acknowledged block
    HighestAcknowledgedBlock: () -> u64,

    // If a block was notable
    /*
      A block is notable if one of three conditions are met:

      1) We activated a key within this block (or explicitly forward to an activated key).
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

    SerializedForwardedOutput: (id: &[u8]) -> Vec<u8>,
  }
);

pub(crate) struct ScannerGlobalDb<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> ScannerGlobalDb<S> {
  pub(crate) fn start_block(getter: &impl Get) -> Option<u64> {
    StartBlock::get(getter)
  }
  pub(crate) fn set_start_block(txn: &mut impl DbTxn, block: u64) {
    StartBlock::set(txn, &block)
  }

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
  /// `activation_block_number` is inclusive, so the key will be scanned for starting at the
  /// specified block.
  pub(crate) fn queue_key(txn: &mut impl DbTxn, activation_block_number: u64, key: KeyFor<S>) {
    // Set the block which has a key activate as notable
    NotableBlock::set(txn, activation_block_number, &());

    // Check this key has never been queued before
    // This should only happen if a malicious supermajority collude, and breaks indexing by the key
    assert!(QueuedKey::get(txn, EncodableG(key)).is_none(), "key being queued was prior queued");
    QueuedKey::set(txn, EncodableG(key), &());

    // Fetch the existing keys
    let mut keys: Vec<SeraiKeyDbEntry<EncodableG<KeyFor<S>>>> =
      ActiveKeys::get(txn).unwrap_or(vec![]);

    // If this new key retires a key, mark the block at which forwarding explicitly occurs notable
    // This lets us obtain synchrony over the transactions we'll make to accomplish this
    if let Some(key_retired_by_this) = keys.last() {
      NotableBlock::set(
        txn,
        Lifetime::calculate::<S>(
          // The 'current block number' used for this calculation
          activation_block_number,
          // The activation block of the key we're getting the lifetime of
          key_retired_by_this.activation_block_number,
          // The activation block of the key which will retire this key
          Some(activation_block_number),
        )
        .block_at_which_forwarding_starts
        .expect(
          "didn't calculate the block forwarding starts at despite passing the next key's info",
        ),
        &(),
      );
    }

    // Push and save the next key
    keys.push(SeraiKeyDbEntry { activation_block_number, key: EncodableG(key) });
    ActiveKeys::set(txn, &keys);
  }
  /// Retire a key.
  ///
  /// The key retired must be the oldest key. There must be another key actively tracked.
  pub(crate) fn retire_key(txn: &mut impl DbTxn, at_block: u64, key: KeyFor<S>) {
    // Set the block which has a key retire as notable
    NotableBlock::set(txn, at_block, &());

    let keys: Vec<SeraiKeyDbEntry<EncodableG<KeyFor<S>>>> =
      ActiveKeys::get(txn).expect("retiring key yet no active keys");

    assert!(keys.len() > 1, "retiring our only key");
    assert_eq!(keys[0].key.0, key, "not retiring the oldest key");

    RetireAt::set(txn, EncodableG(key), &at_block);
  }
  pub(crate) fn tidy_keys(txn: &mut impl DbTxn) {
    let mut keys: Vec<SeraiKeyDbEntry<EncodableG<KeyFor<S>>>> =
      ActiveKeys::get(txn).expect("retiring key yet no active keys");
    let Some(key) = keys.first() else { return };

    // Get the block we're scanning for next
    let block_number = next_to_scan_for_outputs_block::<S>(txn).expect(
      "tidying keys despite never setting the next to scan for block (done on initialization)",
    );
    // If this key is scheduled for retiry...
    if let Some(retire_at) = RetireAt::get(txn, key.key) {
      // And is retired by/at this block...
      if retire_at <= block_number {
        // Remove it from the list of keys
        let key = keys.remove(0);
        ActiveKeys::set(txn, &keys);
        // Also clean up the retiry block
        RetireAt::del(txn, key.key);
      }
    }
  }
  /// Fetch the active keys, as of the next-to-scan-for-outputs Block.
  ///
  /// This means the scan task should scan for all keys returned by this.
  pub(crate) fn active_keys_as_of_next_to_scan_for_outputs_block(
    getter: &impl Get,
  ) -> Option<Vec<SeraiKey<KeyFor<S>>>> {
    // We don't take this as an argument as we don't keep all historical keys in memory
    // If we've scanned block 1,000,000, we can't answer the active keys as of block 0
    let block_number = next_to_scan_for_outputs_block::<S>(getter)?;

    let raw_keys: Vec<SeraiKeyDbEntry<EncodableG<KeyFor<S>>>> = ActiveKeys::get(getter)?;
    let mut keys = Vec::with_capacity(2);
    for i in 0 .. raw_keys.len() {
      // Ensure this key isn't retired
      if let Some(retire_at) = RetireAt::get(getter, raw_keys[i].key) {
        if retire_at <= block_number {
          continue;
        }
      }
      // Ensure this key isn't yet to activate
      if block_number < raw_keys[i].activation_block_number {
        continue;
      }
      let Lifetime { stage, block_at_which_reporting_starts, block_at_which_forwarding_starts } =
        Lifetime::calculate::<S>(
          block_number,
          raw_keys[i].activation_block_number,
          raw_keys.get(i + 1).map(|key| key.activation_block_number),
        );
      keys.push(SeraiKey {
        key: raw_keys[i].key.0,
        stage,
        activation_block_number: raw_keys[i].activation_block_number,
        block_at_which_reporting_starts,
        block_at_which_forwarding_starts,
      });
    }
    assert!(keys.len() <= 2, "more than two keys active");
    Some(keys)
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

  /*
    This is so verbosely named as the DB itself already flags upon external outputs. Specifically,
    if any block yields External outputs to accumulate, we flag it as notable.

    There is the slight edge case where some External outputs are queued for accumulation later. We
    consider those outputs received as of the block they're queued to (maintaining the policy any
    blocks in which we receive outputs is notable).
  */
  pub(crate) fn flag_notable_due_to_non_external_output(txn: &mut impl DbTxn, block_number: u64) {
    assert!(
      NextToPotentiallyReportBlock::get(txn).unwrap() <= block_number,
      "already potentially reported a block we're only now flagging as notable"
    );
    NotableBlock::set(txn, block_number, &());
  }

  pub(crate) fn is_block_notable(getter: &impl Get, number: u64) -> bool {
    NotableBlock::get(getter, number).is_some()
  }

  pub(crate) fn return_address_and_in_instruction_for_forwarded_output(
    getter: &impl Get,
    output: &<OutputFor<S> as ReceivedOutput<KeyFor<S>, AddressFor<S>>>::Id,
  ) -> Option<(Option<AddressFor<S>>, InInstructionWithBalance)> {
    let buf = SerializedForwardedOutput::get(getter, output.as_ref())?;
    let mut buf = buf.as_slice();

    let mut opt = [0xff];
    buf.read_exact(&mut opt).unwrap();
    assert!((opt[0] == 0) || (opt[0] == 1));

    let address = (opt[0] == 1).then(|| AddressFor::<S>::deserialize_reader(&mut buf).unwrap());
    Some((address, InInstructionWithBalance::decode(&mut IoReader(buf)).unwrap()))
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

db_channel! {
  ScannerScanEventuality {
    ScannedBlock: () -> Vec<u8>,
  }
}

pub(crate) struct ScanToEventualityDb<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> ScanToEventualityDb<S> {
  pub(crate) fn send_scan_data(txn: &mut impl DbTxn, block_number: u64, data: &SenderScanData<S>) {
    // If we received an External output to accumulate, or have an External output to forward
    // (meaning we received an External output), or have an External output to return (again
    // meaning we received an External output), set this block as notable due to receiving outputs
    // The non-External output case is covered with `flag_notable_due_to_non_external_output`
    if !(data.received_external_outputs.is_empty() &&
      data.forwards.is_empty() &&
      data.returns.is_empty())
    {
      NotableBlock::set(txn, block_number, &());
    }

    // Save all the forwarded outputs' data
    for forward in &data.forwards {
      let mut buf = vec![];
      if let Some(address) = &forward.return_address {
        buf.write_all(&[1]).unwrap();
        address.serialize(&mut buf).unwrap();
      } else {
        buf.write_all(&[0]).unwrap();
      }
      forward.in_instruction.encode_to(&mut buf);

      SerializedForwardedOutput::set(txn, forward.output.id().as_ref(), &buf);
    }

    let mut buf = vec![];
    buf.write_all(&data.block_number.to_le_bytes()).unwrap();
    buf
      .write_all(&u32::try_from(data.received_external_outputs.len()).unwrap().to_le_bytes())
      .unwrap();
    for output in &data.received_external_outputs {
      output.write(&mut buf).unwrap();
    }
    buf.write_all(&u32::try_from(data.forwards.len()).unwrap().to_le_bytes()).unwrap();
    for output_with_in_instruction in &data.forwards {
      // Only write the output, as we saved the InInstruction above as needed
      output_with_in_instruction.output.write(&mut buf).unwrap();
    }
    buf.write_all(&u32::try_from(data.returns.len()).unwrap().to_le_bytes()).unwrap();
    for output in &data.returns {
      output.write(&mut buf).unwrap();
    }
    ScannedBlock::send(txn, &buf);
  }
  pub(crate) fn recv_scan_data(
    txn: &mut impl DbTxn,
    expected_block_number: u64,
  ) -> ReceiverScanData<S> {
    let data =
      ScannedBlock::try_recv(txn).expect("receiving data for a scanned block not yet sent");
    let mut data = data.as_slice();

    let block_number = {
      let mut block_number = [0; 8];
      data.read_exact(&mut block_number).unwrap();
      u64::from_le_bytes(block_number)
    };
    assert_eq!(
      block_number, expected_block_number,
      "received data for a scanned block distinct than expected"
    );

    let received_external_outputs = {
      let mut len = [0; 4];
      data.read_exact(&mut len).unwrap();
      let len = usize::try_from(u32::from_le_bytes(len)).unwrap();

      let mut received_external_outputs = Vec::with_capacity(len);
      for _ in 0 .. len {
        received_external_outputs.push(OutputFor::<S>::read(&mut data).unwrap());
      }
      received_external_outputs
    };

    let forwards = {
      let mut len = [0; 4];
      data.read_exact(&mut len).unwrap();
      let len = usize::try_from(u32::from_le_bytes(len)).unwrap();

      let mut forwards = Vec::with_capacity(len);
      for _ in 0 .. len {
        forwards.push(OutputFor::<S>::read(&mut data).unwrap());
      }
      forwards
    };

    let returns = {
      let mut len = [0; 4];
      data.read_exact(&mut len).unwrap();
      let len = usize::try_from(u32::from_le_bytes(len)).unwrap();

      let mut returns = Vec::with_capacity(len);
      for _ in 0 .. len {
        returns.push(Return::<S>::read(&mut data).unwrap());
      }
      returns
    };

    ReceiverScanData { block_number, received_external_outputs, forwards, returns }
  }
}

pub(crate) struct Returnable<S: ScannerFeed> {
  pub(crate) return_address: Option<AddressFor<S>>,
  pub(crate) in_instruction: InInstructionWithBalance,
}

impl<S: ScannerFeed> Returnable<S> {
  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let mut opt = [0xff];
    reader.read_exact(&mut opt).unwrap();
    assert!((opt[0] == 0) || (opt[0] == 1));

    let return_address =
      (opt[0] == 1).then(|| AddressFor::<S>::deserialize_reader(reader)).transpose()?;

    let in_instruction =
      InInstructionWithBalance::decode(&mut IoReader(reader)).map_err(io::Error::other)?;
    Ok(Returnable { return_address, in_instruction })
  }
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    if let Some(return_address) = &self.return_address {
      writer.write_all(&[1])?;
      return_address.serialize(writer)?;
    } else {
      writer.write_all(&[0])?;
    }
    self.in_instruction.encode_to(writer);
    Ok(())
  }
}

#[derive(BorshSerialize, BorshDeserialize)]
struct BlockBoundInInstructions {
  block_number: u64,
  returnable_in_instructions: Vec<u8>,
}

db_channel! {
  ScannerScanReport {
    InInstructions: () -> BlockBoundInInstructions,
  }
}

pub(crate) struct InInstructionData<S: ScannerFeed> {
  pub(crate) external_key_for_session_to_sign_batch: KeyFor<S>,
  pub(crate) returnable_in_instructions: Vec<Returnable<S>>,
}

pub(crate) struct ScanToReportDb<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> ScanToReportDb<S> {
  pub(crate) fn send_in_instructions(
    txn: &mut impl DbTxn,
    block_number: u64,
    data: &InInstructionData<S>,
  ) {
    let mut buf = data.external_key_for_session_to_sign_batch.to_bytes().as_ref().to_vec();
    for returnable_in_instruction in &data.returnable_in_instructions {
      returnable_in_instruction.write(&mut buf).unwrap();
    }
    InInstructions::send(
      txn,
      &BlockBoundInInstructions { block_number, returnable_in_instructions: buf },
    );
  }

  pub(crate) fn recv_in_instructions(
    txn: &mut impl DbTxn,
    block_number: u64,
  ) -> InInstructionData<S> {
    let data = InInstructions::try_recv(txn)
      .expect("receiving InInstructions for a scanned block not yet sent");
    assert_eq!(
      block_number, data.block_number,
      "received InInstructions for a scanned block distinct than expected"
    );
    let mut buf = data.returnable_in_instructions.as_slice();

    let external_key_for_session_to_sign_batch = {
      let mut external_key_for_session_to_sign_batch =
        <KeyFor<S> as GroupEncoding>::Repr::default();
      let key_len = external_key_for_session_to_sign_batch.as_ref().len();
      external_key_for_session_to_sign_batch.as_mut().copy_from_slice(&buf[.. key_len]);
      buf = &buf[key_len ..];
      KeyFor::<S>::from_bytes(&external_key_for_session_to_sign_batch).unwrap()
    };

    let mut returnable_in_instructions = vec![];
    while !buf.is_empty() {
      returnable_in_instructions.push(Returnable::read(&mut buf).unwrap());
    }
    InInstructionData { external_key_for_session_to_sign_batch, returnable_in_instructions }
  }
}

db_channel! {
  ScannerSubstrateEventuality {
    Burns: (acknowledged_block: u64) -> Vec<OutInstructionWithBalance>,
  }
}

pub(crate) struct SubstrateToEventualityDb;
impl SubstrateToEventualityDb {
  pub(crate) fn send_burns<S: ScannerFeed>(
    txn: &mut impl DbTxn,
    acknowledged_block: u64,
    burns: Vec<OutInstructionWithBalance>,
  ) {
    // Drop burns less than the dust
    let burns = burns
      .into_iter()
      .filter(|burn| burn.balance.amount.0 >= S::dust(burn.balance.coin).0)
      .collect::<Vec<_>>();
    if !burns.is_empty() {
      Burns::send(txn, acknowledged_block, &burns);
    }
  }

  pub(crate) fn try_recv_burns(
    txn: &mut impl DbTxn,
    acknowledged_block: u64,
  ) -> Option<Vec<OutInstructionWithBalance>> {
    Burns::try_recv(txn, acknowledged_block)
  }
}

mod _public_db {
  use serai_in_instructions_primitives::Batch;

  use serai_db::{Get, DbTxn, create_db, db_channel};

  db_channel! {
    ScannerPublic {
      Batches: () -> Batch,
      BatchesToSign: (key: &[u8]) -> Batch,
      AcknowledgedBatches: (key: &[u8]) -> u32,
      CompletedEventualities: (key: &[u8]) -> [u8; 32],
    }
  }
}

/// The batches to publish.
///
/// This is used for auditing the Batches published to Serai.
pub struct Batches;
impl Batches {
  pub(crate) fn send(txn: &mut impl DbTxn, batch: &Batch) {
    _public_db::Batches::send(txn, batch);
  }

  /// Receive a batch to publish.
  pub fn try_recv(txn: &mut impl DbTxn) -> Option<Batch> {
    _public_db::Batches::try_recv(txn)
  }
}

/// The batches to sign and publish.
///
/// This is used for publishing Batches onto Serai.
pub struct BatchesToSign<K: GroupEncoding>(PhantomData<K>);
impl<K: GroupEncoding> BatchesToSign<K> {
  pub(crate) fn send(txn: &mut impl DbTxn, key: &K, batch: &Batch) {
    _public_db::BatchesToSign::send(txn, key.to_bytes().as_ref(), batch);
  }

  /// Receive a batch to sign and publish.
  pub fn try_recv(txn: &mut impl DbTxn, key: &K) -> Option<Batch> {
    _public_db::BatchesToSign::try_recv(txn, key.to_bytes().as_ref())
  }
}

/// The batches which were acknowledged on-chain.
pub struct AcknowledgedBatches<K: GroupEncoding>(PhantomData<K>);
impl<K: GroupEncoding> AcknowledgedBatches<K> {
  pub(crate) fn send(txn: &mut impl DbTxn, key: &K, batch: u32) {
    _public_db::AcknowledgedBatches::send(txn, key.to_bytes().as_ref(), &batch);
  }

  /// Receive the ID of a batch which was acknowledged.
  pub fn try_recv(txn: &mut impl DbTxn, key: &K) -> Option<u32> {
    _public_db::AcknowledgedBatches::try_recv(txn, key.to_bytes().as_ref())
  }
}

/// The IDs of completed Eventualities found on-chain, within a finalized block.
pub struct CompletedEventualities<K: GroupEncoding>(PhantomData<K>);
impl<K: GroupEncoding> CompletedEventualities<K> {
  pub(crate) fn send(txn: &mut impl DbTxn, key: &K, id: [u8; 32]) {
    _public_db::CompletedEventualities::send(txn, key.to_bytes().as_ref(), &id);
  }

  /// Receive the ID of a completed Eventuality.
  pub fn try_recv(txn: &mut impl DbTxn, key: &K) -> Option<[u8; 32]> {
    _public_db::CompletedEventualities::try_recv(txn, key.to_bytes().as_ref())
  }
}
