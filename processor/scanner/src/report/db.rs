use core::marker::PhantomData;
use std::io::{Read, Write};

use group::GroupEncoding;

use scale::{Encode, Decode, IoReader};
use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::{Get, DbTxn, create_db};

use serai_primitives::Balance;

use crate::{ScannerFeed, KeyFor, AddressFor};

create_db!(
  ScannerReport {
    // The next block to potentially report
    NextToPotentiallyReportBlock: () -> u64,
    // The next Batch ID to use
    NextBatchId: () -> u32,

    // The block number which caused a batch
    BlockNumberForBatch: (batch: u32) -> u64,

    // The external key for the session which should sign a batch
    ExternalKeyForSessionToSignBatch: (batch: u32) -> Vec<u8>,

    // The return addresses for the InInstructions within a Batch
    SerializedReturnAddresses: (batch: u32) -> Vec<u8>,
  }
);

pub(crate) struct ReturnInformation<S: ScannerFeed> {
  pub(crate) address: AddressFor<S>,
  pub(crate) balance: Balance,
}

pub(crate) struct ReportDb<S: ScannerFeed>(PhantomData<S>);
impl<S: ScannerFeed> ReportDb<S> {
  pub(crate) fn set_next_to_potentially_report_block(
    txn: &mut impl DbTxn,
    next_to_potentially_report_block: u64,
  ) {
    NextToPotentiallyReportBlock::set(txn, &next_to_potentially_report_block);
  }
  pub(crate) fn next_to_potentially_report_block(getter: &impl Get) -> Option<u64> {
    NextToPotentiallyReportBlock::get(getter)
  }

  pub(crate) fn acquire_batch_id(txn: &mut impl DbTxn, block_number: u64) -> u32 {
    let id = NextBatchId::get(txn).unwrap_or(0);
    NextBatchId::set(txn, &(id + 1));
    BlockNumberForBatch::set(txn, id, &block_number);
    id
  }

  pub(crate) fn take_block_number_for_batch(txn: &mut impl DbTxn, id: u32) -> Option<u64> {
    let block_number = BlockNumberForBatch::get(txn, id)?;
    BlockNumberForBatch::del(txn, id);
    Some(block_number)
  }

  pub(crate) fn save_external_key_for_session_to_sign_batch(
    txn: &mut impl DbTxn,
    id: u32,
    external_key_for_session_to_sign_batch: &KeyFor<S>,
  ) {
    ExternalKeyForSessionToSignBatch::set(
      txn,
      id,
      &external_key_for_session_to_sign_batch.to_bytes().as_ref().to_vec(),
    );
  }

  pub(crate) fn take_external_key_for_session_to_sign_batch(
    txn: &mut impl DbTxn,
    id: u32,
  ) -> Option<KeyFor<S>> {
    ExternalKeyForSessionToSignBatch::get(txn, id).map(|key_vec| {
      let mut key = <KeyFor<S> as GroupEncoding>::Repr::default();
      key.as_mut().copy_from_slice(&key_vec);
      KeyFor::<S>::from_bytes(&key).unwrap()
    })
  }

  pub(crate) fn save_return_information(
    txn: &mut impl DbTxn,
    id: u32,
    return_information: &Vec<Option<ReturnInformation<S>>>,
  ) {
    let mut buf = Vec::with_capacity(return_information.len() * (32 + 1 + 8));
    for return_information in return_information {
      if let Some(ReturnInformation { address, balance }) = return_information {
        buf.write_all(&[1]).unwrap();
        address.serialize(&mut buf).unwrap();
        balance.encode_to(&mut buf);
      } else {
        buf.write_all(&[0]).unwrap();
      }
    }
    SerializedReturnAddresses::set(txn, id, &buf);
  }
  pub(crate) fn take_return_information(
    txn: &mut impl DbTxn,
    id: u32,
  ) -> Option<Vec<Option<ReturnInformation<S>>>> {
    let buf = SerializedReturnAddresses::get(txn, id)?;
    SerializedReturnAddresses::del(txn, id);
    let mut buf = buf.as_slice();

    let mut res = Vec::with_capacity(buf.len() / (32 + 1 + 8));
    while !buf.is_empty() {
      let mut opt = [0xff];
      buf.read_exact(&mut opt).unwrap();
      assert!((opt[0] == 0) || (opt[0] == 1));

      res.push((opt[0] == 1).then(|| {
        let address = AddressFor::<S>::deserialize_reader(&mut buf).unwrap();
        let balance = Balance::decode(&mut IoReader(&mut buf)).unwrap();
        ReturnInformation { address, balance }
      }));
    }
    Some(res)
  }
}
