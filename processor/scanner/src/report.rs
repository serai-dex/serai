/*
  We only report blocks once both tasks, scanning for received ouputs and eventualities, have
  processed the block. This ensures we've performed all ncessary options.
*/

use serai_db::{Db, DbTxn};

use primitives::{Id, Block};

// TODO: Localize to ReportDb?
use crate::{db::ScannerDb, ScannerFeed};

struct ReportTask<D: Db, S: ScannerFeed> {
  db: D,
  feed: S,
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed> ContinuallyRan for ReportTask<D, S> {
  async fn run_iteration(&mut self) -> Result<bool, String> {
    let highest_reportable = {
      // Fetch the latest scanned and latest checked block
      let next_to_scan = ScannerDb::<S>::next_to_scan_for_outputs_block(&self.db).expect("ReportTask run before writing the start block");
      let next_to_check = ScannerDb::<S>::next_to_check_for_eventualities_block(&self.db).expect("ReportTask run before writing the start block");
      // If we haven't done any work, return
      if (next_to_scan == 0) || (next_to_check == 0) {
        return Ok(false);
      }
      let last_scanned = next_to_scan - 1;
      let last_checked = next_to_check - 1;
      last_scanned.min(last_checked)
    };

    let next_to_potentially_report = ScannerDb::<S>::next_block_to_potentially_report(&self.db).expect("ReportTask run before writing the start block");

    for b in next_to_potentially_report ..= highest_reportable {
      if ScannerDb::<S>::is_block_notable(b) {
        todo!("TODO: Make Batches, which requires handling Forwarded within this crate");
      }

      let mut txn = self.db.txn();
      // Update the next to potentially report block
      ScannerDb::<S>::set_next_to_potentially_report_block(&mut txn, b + 1);
      txn.commit();
    }

    // Run dependents if we decided to report any blocks
    Ok(next_to_potentially_report <= highest_reportable)
  }
}
