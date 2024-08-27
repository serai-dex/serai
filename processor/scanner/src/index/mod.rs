use serai_db::{Get, DbTxn, Db};

use primitives::{task::ContinuallyRan, BlockHeader};

use crate::ScannerFeed;

mod db;
use db::IndexDb;

/// Panics if an unindexed block's ID is requested.
pub(crate) fn block_id(getter: &impl Get, block_number: u64) -> [u8; 32] {
  IndexDb::block_id(getter, block_number)
    .unwrap_or_else(|| panic!("requested block ID for unindexed block {block_number}"))
}

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

impl<D: Db, S: ScannerFeed> IndexFinalizedTask<D, S> {
  pub(crate) async fn new(mut db: D, feed: S, start_block: u64) -> Self {
    if IndexDb::block_id(&db, start_block).is_none() {
      // Fetch the block for its ID
      let block = {
        let mut delay = Self::DELAY_BETWEEN_ITERATIONS;
        loop {
          match feed.unchecked_block_header_by_number(start_block).await {
            Ok(block) => break block,
            Err(e) => {
              log::warn!("IndexFinalizedTask couldn't fetch start block {start_block}: {e:?}");
              tokio::time::sleep(core::time::Duration::from_secs(delay)).await;
              delay += Self::DELAY_BETWEEN_ITERATIONS;
              delay = delay.min(Self::MAX_DELAY_BETWEEN_ITERATIONS);
            }
          };
        }
      };

      // Initialize the DB
      let mut txn = db.txn();
      IndexDb::set_block(&mut txn, start_block, block.id());
      IndexDb::set_latest_finalized_block(&mut txn, start_block);
      txn.commit();
    }

    Self { db, feed }
  }
}

#[async_trait::async_trait]
impl<D: Db, S: ScannerFeed> ContinuallyRan for IndexFinalizedTask<D, S> {
  async fn run_iteration(&mut self) -> Result<bool, String> {
    // Fetch the latest finalized block
    let our_latest_finalized = IndexDb::latest_finalized_block(&self.db)
      .expect("IndexTask run before writing the start block");
    let latest_finalized = match self.feed.latest_finalized_block_number().await {
      Ok(latest_finalized) => latest_finalized,
      Err(e) => Err(format!("couldn't fetch the latest finalized block number: {e:?}"))?,
    };

    if latest_finalized < our_latest_finalized {
      // Explicitly log this as an error as returned ephemeral errors are logged with debug
      // This doesn't panic as the node should sync along our indexed chain, and if it doesn't,
      // we'll panic at that point in time
      log::error!(
        "node is out of sync, latest finalized {} is behind our indexed {}",
        latest_finalized,
        our_latest_finalized
      );
      Err("node is out of sync".to_string())?;
    }

    // Index the hashes of all blocks until the latest finalized block
    for b in (our_latest_finalized + 1) ..= latest_finalized {
      let block = match self.feed.unchecked_block_header_by_number(b).await {
        Ok(block) => block,
        Err(e) => Err(format!("couldn't fetch block {b}: {e:?}"))?,
      };

      // Check this descends from our indexed chain
      {
        let expected_parent =
          IndexDb::block_id(&self.db, b - 1).expect("didn't have the ID of the prior block");
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
      IndexDb::set_block(&mut txn, b, block.id());
      IndexDb::set_latest_finalized_block(&mut txn, b);
      txn.commit();
    }

    // Have dependents run if we updated the latest finalized block
    Ok(our_latest_finalized != latest_finalized)
  }
}
