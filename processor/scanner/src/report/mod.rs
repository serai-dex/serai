use core::marker::PhantomData;

use scale::Encode;
use serai_db::{DbTxn, Db};

use serai_primitives::BlockHash;
use serai_in_instructions_primitives::{MAX_BATCH_SIZE, Batch};

use crate::{
  db::{ScannerGlobalDb, ScanToReportDb},
  index,
  scan::next_to_scan_for_outputs_block,
  ScannerFeed, ContinuallyRan,
};

mod db;
use db::ReportDb;

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
    if ReportDb::next_to_potentially_report_block(&db).is_none() {
      // Initialize the DB
      let mut txn = db.txn();
      ReportDb::set_next_to_potentially_report_block(&mut txn, start_block);
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

    let next_to_potentially_report = ReportDb::next_to_potentially_report_block(&self.db)
      .expect("ReportTask run before writing the start block");

    for b in next_to_potentially_report ..= highest_reportable {
      let mut txn = self.db.txn();

      // Receive the InInstructions for this block
      // We always do this as we can't trivially tell if we should recv InInstructions before we do
      let in_instructions = ScanToReportDb::<S>::recv_in_instructions(&mut txn, b);
      let notable = ScannerGlobalDb::<S>::is_block_notable(&txn, b);
      if !notable {
        assert!(in_instructions.is_empty(), "block wasn't notable yet had InInstructions");
      }
      // If this block is notable, create the Batch(s) for it
      if notable {
        let network = S::NETWORK;
        let block_hash = index::block_id(&txn, b);
        let mut batch_id = ReportDb::acquire_batch_id(&mut txn);

        // start with empty batch
        let mut batches =
          vec![Batch { network, id: batch_id, block: BlockHash(block_hash), instructions: vec![] }];

        for instruction in in_instructions {
          let batch = batches.last_mut().unwrap();
          batch.instructions.push(instruction);

          // check if batch is over-size
          if batch.encode().len() > MAX_BATCH_SIZE {
            // pop the last instruction so it's back in size
            let instruction = batch.instructions.pop().unwrap();

            // bump the id for the new batch
            batch_id = ReportDb::acquire_batch_id(&mut txn);

            // make a new batch with this instruction included
            batches.push(Batch {
              network,
              id: batch_id,
              block: BlockHash(block_hash),
              instructions: vec![instruction],
            });
          }
        }

        todo!("TODO: Set/emit batches");
      }

      // Update the next to potentially report block
      ReportDb::set_next_to_potentially_report_block(&mut txn, b + 1);

      txn.commit();
    }

    // Run dependents if we decided to report any blocks
    Ok(next_to_potentially_report <= highest_reportable)
  }
}
