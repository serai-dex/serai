use core::marker::PhantomData;

use serai_db::{Db, DbTxn};

use primitives::{Id, Block};

// TODO: Localize to SafeDb?
use crate::{db::ScannerDb, ScannerFeed};

/*
  We mark blocks safe to scan when they're no more than `(CONFIRMATIONS - 1)` blocks after the
  oldest notable block still pending acknowledgement (creating a window of length `CONFIRMATIONS`
  when including the block pending acknowledgement). This means that if all known notable blocks
  have been acknowledged, and a stretch of non-notable blocks occurs, they'll automatically be
  marked safe to scan (since they come before the next oldest notable block still pending
  acknowledgement).

  This design lets Serai safely schedule events `CONFIRMATIONS` blocks after the latest
  acknowledged block. For an exhaustive proof of this, please see `mini`.
*/
struct SafeToScanTask<D: Db, S: ScannerFeed> {
  db: D,
  _S: PhantomData<S>,
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed> ContinuallyRan for SafeToScanTask<D, S> {
  async fn run_iteration(&mut self) -> Result<bool, String> {
    // First, we fetch the highest acknowledged block
    let Some(highest_acknowledged_block) = ScannerDb::<S>::highest_acknowledged_block(&self.db) else {
      // If no blocks have been acknowledged, we don't mark any safe
      // Once the start block (implicitly safe) has been acknowledged, we proceed from there
      return Ok(false);
    };

    let latest_block_known_if_pending_acknowledgement = {
      // The next block to potentially report comes after all blocks we've decided to report or not
      // If we've decided to report (or not report) a block, we know if it needs acknowledgement
      // (and accordingly is pending acknowledgement)
      // Accordingly, the block immediately before this is the latest block with a known status
      ScannerDb::<S>::next_block_to_potentially_report(&self.db).expect("SafeToScanTask run before writing the start block") - 1
    };

    let mut oldest_pending_acknowledgement = None;
    for b in (highest_acknowledged_block + 1) ..= latest_block_known_if_pending_acknowledgement {
      // If the block isn't notable, immediately flag it as acknowledged
      if !ScannerDb::<S>::is_block_notable(b) {
        let mut txn = self.db.txn();
        ScannerDb::<S>::set_highest_acknowledged_block(&mut txn, b);
        txn.commit();
        continue;
      }

      oldest_pending_acknowledgement = Some(b);
      break;
    }

    // `oldest_pending_acknowledgement` is now the oldest block pending acknowledgement or `None`
    // If it's `None`, then we were able to implicitly acknowledge all blocks within this span
    // Since the safe block is `(CONFIRMATIONS - 1)` blocks after the oldest block still pending
    // acknowledgement, and the oldest block still pending acknowledgement is in the future,
    // we know the safe block to scan to is
    // `>= latest_block_known_if_pending_acknowledgement + (CONFIRMATIONS - 1)`
    let oldest_pending_acknowledgement = oldest_pending_acknowledgement.unwrap_or(latest_block_known_if_pending_acknowledgement);

    // Update the latest scannable block
    let mut txn = self.db.txn();
    ScannerDb::<S>::set_latest_scannable_block(oldest_pending_acknowledgement + (CONFIRMATIONS - 1));
    txn.commit();

    Ok(next_to_potentially_report <= highest_reportable)
  }
}
