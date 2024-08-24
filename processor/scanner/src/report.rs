use scale::Encode;
use serai_db::{Db, DbTxn};

use serai_primitives::BlockHash;
use serai_in_instructions_primitives::{MAX_BATCH_SIZE, Batch};
use primitives::{Id, OutputType, Block};

// TODO: Localize to ReportDb?
use crate::{db::ScannerDb, ScannerFeed, ContinuallyRan};

/*
  This task produces Batches for notable blocks, with all InInstructions, in an ordered fashion.

  We only report blocks once both tasks, scanning for received outputs and checking for resolved
  Eventualities, have processed the block. This ensures we know if this block is notable, and have
  the InInstructions for it.
*/
struct ReportTask<D: Db, S: ScannerFeed> {
  db: D,
  feed: S,
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed> ContinuallyRan for ReportTask<D, S> {
  async fn run_iteration(&mut self) -> Result<bool, String> {
    let highest_reportable = {
      // Fetch the next to scan block
      let next_to_scan = ScannerDb::<S>::next_to_scan_for_outputs_block(&self.db)
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

    let next_to_potentially_report = ScannerDb::<S>::next_to_potentially_report_block(&self.db)
      .expect("ReportTask run before writing the start block");

    for b in next_to_potentially_report ..= highest_reportable {
      let mut txn = self.db.txn();

      if ScannerDb::<S>::is_block_notable(&txn, b) {
        let in_instructions = ScannerDb::<S>::in_instructions(&txn, b)
          .expect("reporting block which didn't set its InInstructions");

        let network = S::NETWORK;
        let block_hash =
          ScannerDb::<S>::block_id(&txn, b).expect("reporting block we didn't save the ID for");
        let mut batch_id = ScannerDb::<S>::acquire_batch_id(txn);

        // start with empty batch
        let mut batches =
          vec![Batch { network, id: batch_id, block: BlockHash(block_hash), instructions: vec![] }];

        for instruction in in_instructions {
          let batch = batches.last_mut().unwrap();
          batch.instructions.push(instruction.in_instruction);

          // check if batch is over-size
          if batch.encode().len() > MAX_BATCH_SIZE {
            // pop the last instruction so it's back in size
            let instruction = batch.instructions.pop().unwrap();

            // bump the id for the new batch
            batch_id = ScannerDb::<S>::acquire_batch_id(txn);

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
      ScannerDb::<S>::set_next_to_potentially_report_block(&mut txn, b + 1);

      txn.commit();
    }

    // Run dependents if we decided to report any blocks
    Ok(next_to_potentially_report <= highest_reportable)
  }
}
