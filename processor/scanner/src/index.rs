use serai_db::{Db, DbTxn};

use primitives::{Id, Block};

// TODO: Localize to IndexDb?
use crate::{db::ScannerDb, ScannerFeed, ContinuallyRan};

/*
  This processor should build its own index of the blockchain, yet only for finalized blocks which
  are safe to process. For Proof of Work blockchains, which only have probabilistic finality, these
  are the set of sufficiently confirmed blocks. For blockchains with finality, these are the
  finalized blocks.

  This task finds the finalized blocks, verifies they're continguous, and saves their IDs.
*/
struct IndexFinalizedTask<D: Db, S: ScannerFeed> {
  db: D,
  feed: S,
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed> ContinuallyRan for IndexFinalizedTask<D, S> {
  async fn run_instance(&mut self) -> Result<(), String> {
    // Fetch the latest finalized block
    let our_latest_finalized = ScannerDb::<S>::latest_finalized_block(&self.db)
      .expect("IndexTask run before writing the start block");
    let latest_finalized = match self.feed.latest_finalized_block_number().await {
      Ok(latest_finalized) => latest_finalized,
      Err(e) => Err(format!("couldn't fetch the latest finalized block number: {e:?}"))?,
    };

    // Index the hashes of all blocks until the latest finalized block
    for b in (our_latest_finalized + 1) ..= latest_finalized {
      let block = match self.feed.block_by_number(b).await {
        Ok(block) => block,
        Err(e) => Err(format!("couldn't fetch block {b}: {e:?}"))?,
      };

      // Check this descends from our indexed chain
      {
        let expected_parent =
          ScannerDb::<S>::block_id(&self.db, b - 1).expect("didn't have the ID of the prior block");
        if block.parent() != expected_parent {
          panic!(
            "current finalized block (#{b}, {}) doesn't build off finalized block (#{}, {})",
            hex::encode(block.parent()),
            b - 1,
            hex::encode(expected_parent)
          );
        }
      }

      // Update the latest finalized block
      let mut txn = self.db.txn();
      ScannerDb::<S>::set_block(&mut txn, b, block.id());
      ScannerDb::<S>::set_latest_finalized_block(&mut txn, b);
      txn.commit();
    }

    Ok(())
  }
}

/*
  The processor can't index the blockchain unilaterally. It needs to develop a totally ordered view
  of the blockchain. That requires consensus with other validators on when certain keys are set to
  activate (and retire). We solve this by only scanning `n` blocks ahead of the last agreed upon
  block, then waiting for Serai to acknowledge the block. This lets us safely schedule events after
  this `n` block window (as demonstrated/proven with `mini`).

  TODO
*/
