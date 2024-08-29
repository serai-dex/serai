use serai_db::{Get, DbTxn, create_db};

create_db!(
  ScannerReport {
    // The next block to potentially report
    NextToPotentiallyReportBlock: () -> u64,
    // The next Batch ID to use
    NextBatchId: () -> u32,
  }
);

pub(crate) struct ReportDb;
impl ReportDb {
  pub(crate) fn set_next_to_potentially_report_block(
    txn: &mut impl DbTxn,
    next_to_potentially_report_block: u64,
  ) {
    NextToPotentiallyReportBlock::set(txn, &next_to_potentially_report_block);
  }
  pub(crate) fn next_to_potentially_report_block(getter: &impl Get) -> Option<u64> {
    NextToPotentiallyReportBlock::get(getter)
  }

  pub(crate) fn acquire_batch_id(txn: &mut impl DbTxn) -> u32 {
    let id = NextBatchId::get(txn).unwrap_or(0);
    NextBatchId::set(txn, &(id + 1));
    id
  }
}
