use serai_db::{Db, DbTxn};

use primitives::{Id, ReceivedOutput, Block};

// TODO: Localize to EventualityDb?
use crate::{db::ScannerDb, ScannerFeed, ContinuallyRan};

/*
  Note: The following assumes there's some value, `CONFIRMATIONS`, and the finalized block we
  operate on is `CONFIRMATIONS` blocks deep. This is true for Proof-of-Work chains yet not the API
  actively used here.

  When we scan a block, we receive outputs. When this block is acknowledged, we accumulate those
  outputs into some scheduler, potentially causing certain transactions to begin their signing
  protocol.

  Despite only scanning blocks with `CONFIRMATIONS`, we cannot assume that these transactions (in
  their signed form) will only appear after `CONFIRMATIONS`. For `CONFIRMATIONS = 10`, the scanned
  block's number being `1`, the blockchain will have blocks with numbers `0 ..= 10`. While this
  implies the earliest the transaction will appear is when the block number is `11`, which is
  `1 + CONFIRMATIONS` (the number of the scanned block, plus the confirmations), this isn't
  guaranteed.

  A reorganization could occur which causes all unconfirmed blocks to be replaced, with the new
  blockchain having the signed transaction present immediately.

  This means that in order to detect Eventuality completions, we can only check block `b+1` once
  we've acknowledged block `b`, accumulated its outputs, triggered any transactions, and prepared
  for their Eventualities. This is important as both the completion of Eventualities, and the scan
  process, may cause a block to be considered notable (where notable blocks must be perfectly
  ordered).

  We do not want to fully serialize the scan flow solely because the Eventuality flow must be. If
  the time to scan, acknowledge, and intake a block ever exceeded the block time, we'd form a
  backlog.

  The solution is to form a window of blocks we can scan/acknowledge/intake, safely, such that we
  only form a backlog if the latency for a block exceeds the duration of the entire window (the
  amount of blocks in the window * the block time).

  By considering the block an Eventuality resolves not as the block it does, yet the block a window
  later, we enable the following flow:

  - The scanner scans within its window, submitting blocks for acknowledgement.
  - We have the blocks acknowledged (the consensus protocol handling this in parallel).
  - The scanner checks for Eventualities completed following acknowledged blocks.
  - If all Eventualities for a retiring multisig have been cleared, the notable block is one window
    later.
  - The start of the window shifts to the last block we've checked for Eventualities. This means
    the end of the window is the block we just set as notable, and yes, once that's scanned we can
    successfully publish a batch for it in a canonical fashion.

  This forms a backlog only if the latency of scanning, acknowledgement, and intake (including
  checking Eventualities) exceeds the window duration (the desired property).
*/
struct EventualityTask<D: Db, S: ScannerFeed> {
  db: D,
  feed: S,
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed> ContinuallyRan for EventualityTask<D, S> {
  async fn run_iteration(&mut self) -> Result<bool, String> {
    /*
      The set of Eventualities only increase when a block is acknowledged. Accordingly, we can only
      iterate up to (and including) the block currently pending acknowledgement. "including" is
      because even if block `b` causes new Eventualities, they'll only potentially resolve in block
      `b + 1`.

      We only know blocks will need acknowledgement *for sure* if they were scanned. The only other
      causes are key activation and retirement (both scheduled outside the scan window). This makes
      the exclusive upper bound the *next block to scan*.
    */
    let exclusive_upper_bound = {
      // Fetch the next to scan block
      let next_to_scan = ScannerDb::<S>::next_to_scan_for_outputs_block(&self.db)
        .expect("EventualityTask run before writing the start block");
      // If we haven't done any work, return
      if next_to_scan == 0 {
        return Ok(false);
      }
      next_to_scan
    };

    // Fetch the highest acknowledged block
    let highest_acknowledged = ScannerDb::<S>::highest_acknowledged_block(&self.db)
      .expect("EventualityTask run before writing the start block");

    // Fetch the next block to check
    let next_to_check = ScannerDb::<S>::next_to_check_for_eventualities_block(&self.db)
      .expect("EventualityTask run before writing the start block");

    // Check all blocks
    let mut iterated = false;
    for b in next_to_check .. exclusive_upper_bound {
      // If the prior block was notable *and* not acknowledged, break
      // This is so if it caused any Eventualities (which may resolve this block), we have them
      {
        // This `- 1` is safe as next to check is bound to be non-zero
        // This is possible since even if we receive coins in block 0, any transactions we'd make
        // would resolve in block 1 (the first block we'll check under this non-zero rule)
        let prior_block = b - 1;
        if ScannerDb::<S>::is_block_notable(&self.db, prior_block) &&
          (prior_block > highest_acknowledged)
        {
          break;
        }
      }

      iterated = true;

      // TODO: Not only check/clear eventualities, if this eventuality forwarded an output, queue
      // it to be reported in however many blocks
      todo!("TODO");

      let mut txn = self.db.txn();
      // Update the next to check block
      ScannerDb::<S>::set_next_to_check_for_eventualities_block(&mut txn, next_to_check);
      txn.commit();
    }

    // Run dependents if we successfully checked any blocks
    Ok(iterated)
  }
}
