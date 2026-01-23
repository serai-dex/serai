use core::future::Future;

use serai_db::{Get, DbTxn as _, Db};
use primitives::{task::ContinuallyRan, BlockHeader as _};

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
pub(crate) struct IndexTask<D: Db, S: ScannerFeed> {
  db: D,
  feed: S,
}

impl<D: Db, S: ScannerFeed> IndexTask<D, S> {
  pub(crate) async fn new(mut db: D, feed: S, start_block: u64) -> Self {
    if IndexDb::block_id(&db, start_block).is_none() {
      // Fetch the block for its ID
      let block = {
        let mut delay = Self::DELAY_BETWEEN_ITERATIONS;
        loop {
          // loop until the given start block is finalized
          match feed.latest_finalized_block_number().await {
            Ok(latest_finalized) => {
              if latest_finalized >= start_block {
                // Get the block from the chain
                match feed.unchecked_block_header_by_number(start_block).await {
                  Ok(block) => break block,
                  Err(e) => {
                    log::warn!("IndexTask couldn't fetch start block {start_block}: {e:?}");
                  }
                };
              }
              log::warn!("IndexTask start block {start_block} is not yet finalized");
            }
            Err(e) => {
              log::warn!("IndexTask couldn't fetch latest finalized block number: {e:?}");
            }
          }

          tokio::time::sleep(core::time::Duration::from_secs(delay)).await;
          delay += Self::DELAY_BETWEEN_ITERATIONS;
          delay = delay.min(Self::MAX_DELAY_BETWEEN_ITERATIONS);
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

impl<D: Db, S: ScannerFeed> ContinuallyRan for IndexTask<D, S> {
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      // Fetch the latest finalized block
      let our_latest_finalized = IndexDb::latest_finalized_block(&self.db)
        .expect("IndexTask run before writing the start block");
      let latest_finalized = match self.feed.latest_finalized_block_number().await {
        Ok(latest_finalized) => latest_finalized,
        Err(e) => Err(format!("couldn't fetch the latest finalized block number: {e:?}"))?,
      };

      #[expect(clippy::uninlined_format_args)]
      if latest_finalized < our_latest_finalized {
        // Explicitly log this as an error as returned ephemeral errors are logged with debug
        // This doesn't panic as the node should sync along our indexed chain, and if it doesn't,
        // we'll panic at that point in time
        log::error!(
          "node is out of sync, latest finalized ({}) is behind our indexed ({})",
          latest_finalized,
          our_latest_finalized
        );
        Err("node is out of sync".to_owned())?;
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
          assert_eq!(
            block.parent(),
            expected_parent,
            "current finalized block (#{b}, {}) doesn't build off finalized block (#{}, {})",
            hex::encode(block.parent()),
            b - 1,
            hex::encode(expected_parent)
          );
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
}

/// Generic tests for the index task. These should be plug-and-play with an implemented ScannerFeed.
#[cfg(feature = "tests")]
pub mod tests {
  use primitives::task::ContinuallyRan;
  use serai_db::{new_rocksdb, Db};
  use tempfile::TempDir;

  use core::future::Future;

  use crate::{
    ScannerFeed,
    index::{IndexTask, db::IndexDb},
  };

  /// A trait that defines fn's a caller should implement for each chain.
  pub trait DaemonHelper: 'static + Send + Sync + Clone {
    /// Reset the blockchain state.
    fn reset_chain(&self) -> impl Send + Future<Output = ()>;

    /// Add 1 block to the chain.
    fn add_block(&self) -> impl Send + Future<Output = ()>;

    /// There should be at least 1 finalized block in the chain after this executes.
    fn setup_finalized_block(&self) -> impl Send + Future<Output = ()>;
  }

  async fn init_task<D: Db, S: ScannerFeed>(db: D, feed: S, start_block: u64) -> IndexTask<D, S> {
    assert!(IndexDb::latest_finalized_block(&db).is_none());
    assert!(IndexDb::block_id(&db, start_block).is_none());

    let index_task = IndexTask::new(db.clone(), feed.clone(), start_block).await;

    // Assert expected DB state after new
    let our_latest_finalized =
      IndexDb::latest_finalized_block(&db).expect("Expected latest finalized");
    assert_eq!(our_latest_finalized, start_block);
    let res = feed.block_by_number(&db, start_block).await;
    assert!(!res.is_err());

    index_task
  }

  async fn init_test(
    feed: impl ScannerFeed,
  ) -> (TempDir, impl Db, u64, IndexTask<impl Db, impl ScannerFeed>) {
    let temp_dir = TempDir::new().unwrap();
    let temp_db = new_rocksdb(temp_dir.path().to_str().unwrap());

    let start_block = feed.latest_finalized_block_number().await.unwrap();

    let index_task = init_task(temp_db.clone(), feed.clone(), start_block).await;

    (temp_dir, temp_db, start_block, index_task)
  }

  /// Test initializing a new scan task.
  async fn new_index_task<S: ScannerFeed, D: DaemonHelper>(feed: S, daemon: D) {
    daemon.reset_chain().await;
    daemon.add_block().await;
    init_test(feed).await;
  }

  /// Test an iteration of the index task without any change to the chain state.
  async fn no_expected_change<S: ScannerFeed, D: DaemonHelper>(feed: S, daemon: D) {
    daemon.reset_chain().await;
    daemon.setup_finalized_block().await;

    let (_temp_dir, _, _, mut index_task) = init_test(feed).await;

    // We should be able to complete an iteration without erroring
    let res = index_task.run_iteration().await;
    assert!(!res.is_err());

    // Since the chain did not change since we initialized our IndexTask,
    // then the latest finalized block shouldn't have changed either
    let latest_finalized_updated = res.unwrap();
    assert!(!latest_finalized_updated);
  }

  /// Test an iteration of the index task after advancing the chain one block.
  async fn advance_one_block<S: ScannerFeed, D: DaemonHelper>(feed: S, daemon: D) {
    daemon.reset_chain().await;
    daemon.setup_finalized_block().await;

    let (_temp_dir, temp_db, start_block, mut index_task) = init_test(feed.clone()).await;

    // Advance the chain 1 block so that the latest finalized advances by 1
    daemon.add_block().await;

    // We should be able to complete an iteration without erroring
    let res = index_task.run_iteration().await;
    assert!(!res.is_err());

    // The latest finalized should have updated
    let latest_finalized_updated = res.unwrap();
    assert!(latest_finalized_updated);

    // The latest finalized in the db should be expected
    let new_latest_finalized = start_block + 1;
    let our_latest_finalized =
      IndexDb::latest_finalized_block(&temp_db).expect("Expected new latest finalized");
    assert_eq!(our_latest_finalized, new_latest_finalized);

    // The block id's should all match up with the chain
    for b in start_block..=new_latest_finalized {
      let res = feed.clone().block_by_number(&temp_db, b).await;
      assert!(!res.is_err());
    }

    // Next iteration there should be no change
    let res = index_task.run_iteration().await;
    assert!(!res.is_err());
    let latest_finalized_updated = res.unwrap();
    assert!(!latest_finalized_updated);
  }

  /// Test the index task manages various circumstances correctly.
  pub async fn index_task_tests<S: ScannerFeed, D: DaemonHelper>(feed: S, daemon: D) {
    new_index_task(feed.clone(), daemon.clone()).await;
    no_expected_change(feed.clone(), daemon.clone()).await;
    advance_one_block(feed.clone(), daemon.clone()).await;

    // TODO: test the index task can recover from a reorg
  }
}
