use core::marker::PhantomData;

use scale::Encode;
use serai_db::{DbTxn, Db};

use serai_primitives::BlockHash;
use serai_in_instructions_primitives::{MAX_BATCH_SIZE, Batch};

use primitives::task::ContinuallyRan;
use crate::{
  db::{Returnable, ScannerGlobalDb, InInstructionData, ScanToReportDb, BatchToSign},
  index,
  scan::next_to_scan_for_outputs_block,
  ScannerFeed, KeyFor,
};

mod db;
pub(crate) use db::ReturnInformation;
use db::ReportDb;

pub(crate) fn take_block_number_for_batch<S: ScannerFeed>(
  txn: &mut impl DbTxn,
  id: u32,
) -> Option<u64> {
  ReportDb::<S>::take_block_number_for_batch(txn, id)
}

pub(crate) fn take_external_key_for_session_to_sign_batch<S: ScannerFeed>(
  txn: &mut impl DbTxn,
  id: u32,
) -> Option<KeyFor<S>> {
  ReportDb::<S>::take_external_key_for_session_to_sign_batch(txn, id)
}

pub(crate) fn take_return_information<S: ScannerFeed>(
  txn: &mut impl DbTxn,
  id: u32,
) -> Option<Vec<Option<ReturnInformation<S>>>> {
  ReportDb::<S>::take_return_information(txn, id)
}

/*
  This task produces Batches for notable blocks, with all InInstructions, in an ordered fashion.

  We only report blocks once both tasks, scanning for received outputs and checking for resolved
  Eventualities, have processed the block. This ensures we know if this block is notable, and have
  the InInstructions for it.
*/
#[allow(non_snake_case)]
pub(crate) struct ReportTask<D: Db, S: ScannerFeed> {
  db: D,
  _S: PhantomData<S>,
}

impl<D: Db, S: ScannerFeed> ReportTask<D, S> {
  pub(crate) fn new(mut db: D, start_block: u64) -> Self {
    if ReportDb::<S>::next_to_potentially_report_block(&db).is_none() {
      // Initialize the DB
      let mut txn = db.txn();
      ReportDb::<S>::set_next_to_potentially_report_block(&mut txn, start_block);
      txn.commit();
    }

    Self { db, _S: PhantomData }
  }
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed> ContinuallyRan for ReportTask<D, S> {
  async fn run_iteration(&mut self) -> Result<bool, String> {
    let highest_reportable = {
      // Fetch the next to scan block
      let next_to_scan = next_to_scan_for_outputs_block::<S>(&self.db)
        .expect("ReportTask run before writing the start block");
      // If we haven't done any work, return
      if next_to_scan == 0 {
        return Ok(false);
      }
      // The last scanned block is the block prior to this
      #[allow(clippy::let_and_return)]
      let last_scanned = next_to_scan - 1;
      // The last scanned block is the highest reportable block as we only scan blocks within a
      // window where it's safe to immediately report the block
      // See `eventuality.rs` for more info
      last_scanned
    };

    let next_to_potentially_report = ReportDb::<S>::next_to_potentially_report_block(&self.db)
      .expect("ReportTask run before writing the start block");

    for b in next_to_potentially_report ..= highest_reportable {
      let mut txn = self.db.txn();

      // Receive the InInstructions for this block
      // We always do this as we can't trivially tell if we should recv InInstructions before we do
      let InInstructionData {
        external_key_for_session_to_sign_batch,
        returnable_in_instructions: in_instructions,
      } = ScanToReportDb::<S>::recv_in_instructions(&mut txn, b);
      let notable = ScannerGlobalDb::<S>::is_block_notable(&txn, b);
      if !notable {
        assert!(in_instructions.is_empty(), "block wasn't notable yet had InInstructions");
      }
      // If this block is notable, create the Batch(s) for it
      if notable {
        let network = S::NETWORK;
        let block_hash = index::block_id(&txn, b);
        let mut batch_id = ReportDb::<S>::acquire_batch_id(&mut txn, b);

        // start with empty batch
        let mut batches =
          vec![Batch { network, id: batch_id, block: BlockHash(block_hash), instructions: vec![] }];
        // We also track the return information for the InInstructions within a Batch in case they
        // error
        let mut return_information = vec![vec![]];

        for Returnable { return_address, in_instruction } in in_instructions {
          let balance = in_instruction.balance;

          let batch = batches.last_mut().unwrap();
          batch.instructions.push(in_instruction);

          // check if batch is over-size
          if batch.encode().len() > MAX_BATCH_SIZE {
            // pop the last instruction so it's back in size
            let in_instruction = batch.instructions.pop().unwrap();

            // bump the id for the new batch
            batch_id = ReportDb::<S>::acquire_batch_id(&mut txn, b);

            // make a new batch with this instruction included
            batches.push(Batch {
              network,
              id: batch_id,
              block: BlockHash(block_hash),
              instructions: vec![in_instruction],
            });
            // Since we're allocating a new batch, allocate a new set of return addresses for it
            return_information.push(vec![]);
          }

          // For the set of return addresses for the InInstructions for the batch we just pushed
          // onto, push this InInstruction's return addresses
          return_information
            .last_mut()
            .unwrap()
            .push(return_address.map(|address| ReturnInformation { address, balance }));
        }

        // Save the return addresses to the database
        assert_eq!(batches.len(), return_information.len());
        for (batch, return_information) in batches.iter().zip(&return_information) {
          assert_eq!(batch.instructions.len(), return_information.len());
          ReportDb::<S>::save_external_key_for_session_to_sign_batch(
            &mut txn,
            batch.id,
            &external_key_for_session_to_sign_batch,
          );
          ReportDb::<S>::save_return_information(&mut txn, batch.id, return_information);
        }

        for batch in batches {
          BatchToSign::send(&mut txn, &external_key_for_session_to_sign_batch, &batch);
        }
      }

      // Update the next to potentially report block
      ReportDb::<S>::set_next_to_potentially_report_block(&mut txn, b + 1);

      txn.commit();
    }

    // Run dependents if we decided to report any blocks
    Ok(next_to_potentially_report <= highest_reportable)
  }
}
