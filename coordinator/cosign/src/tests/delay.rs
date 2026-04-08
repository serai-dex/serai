use crate::{delay::*, evaluator::*, tests::*};

fn now_secs() -> u64 {
  now_timestamp().as_secs()
}

struct DelayTest {
  db: MemDb,
}

impl Default for DelayTest {
  fn default() -> Self {
    Self { db: MemDb::new() }
  }
}

impl IntoTask for DelayTest {
  type Task = CosignDelayTask<MemDb>;

  fn task(&self) -> Self::Task {
    CosignDelayTask { db: self.db.clone() }
  }
}

impl DelayTest {
  pub fn new() -> (Self, Instant) {
    let start = std::time::Instant::now();
    (Self::default(), start)
  }
}

/// Verify delay's post-run DB invariants.
///
/// After a successful task run, `CosignedBlocks` should be consumed and
/// `LatestCosignedBlockNumber` point to the expected last block number.
fn verify_db_invariants(db: &MemDb, expected_latest_block: Option<u64>) {
  let actual = LatestCosignedBlockNumber::get(db);
  let cosigned_pending = CosignedBlocks::peek(db).is_some();

  assert_eq!(actual, expected_latest_block, "LatestCosignedBlockNumber mismatch");
  assert!(!cosigned_pending, "CosignedBlocks should be fully consumed");
}

#[tokio::test]
async fn updates_latest_finalized_block_after_ack_delay() {
  *INIT_LOGGER;
  let (mut test, start) = DelayTest::new();

  // Returns false (made no progress) on no CosignedBlocks
  {
    let mut task = test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
    verify_db_invariants(&test.db, None);
  }

  // Multiple blocks with the same evaluated_time sleep only for ACKNOWLEDGEMENT_DELAY
  {
    let mut txn = test.db.txn();

    {
      let now = now_secs();
      CosignedBlocks::send(&mut txn, &(0, now, true));
      CosignedBlocks::send(&mut txn, &(1, now, true));
      CosignedBlocks::send(&mut txn, &(2, now, true));
      txn.commit();
    }

    let mut task = test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&test.db, Some(2));
  }

  serai_env::log::info!("Blocks 0-2 processed in {:?}", start.elapsed());
  let start = Instant::now();

  // Timestamps decreasing, given their time_valid already passed during
  // the 1st sleep, none need to sleep after the 1st block
  {
    let mut txn = test.db.txn();

    {
      let now = now_secs();
      CosignedBlocks::send(&mut txn, &(3, now, true));
      CosignedBlocks::send(&mut txn, &(4, now - 5, true));
      CosignedBlocks::send(&mut txn, &(5, now - 10, true));
      txn.commit();
    }

    let mut task = test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&test.db, Some(5));
  }

  serai_env::log::info!("Blocks 3-5 processed in {:?}", start.elapsed());
  let start = Instant::now();

  // Timestamps increasing in order
  // each block sleeps for a slight amount
  {
    let mut txn = test.db.txn();

    {
      let now = now_secs();
      CosignedBlocks::send(&mut txn, &(6, now, true));
      CosignedBlocks::send(&mut txn, &(7, now + 5, true));
      CosignedBlocks::send(&mut txn, &(8, now + 10, true));
      txn.commit();
    }

    let mut task = test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&test.db, Some(8));
  }

  serai_env::log::info!("Blocks 6-8 processed in {:?}", start.elapsed());

  // has_events=false blocks are marked as cosigned immediately, no sleep
  {
    let mut txn = test.db.txn();
    // the time_evaluated timestamp doesn't matter here since it will be skipped
    CosignedBlocks::send(&mut txn, &(9, OsRng.next_u64(), false));
    CosignedBlocks::send(&mut txn, &(10, OsRng.next_u64(), false));
    CosignedBlocks::send(&mut txn, &(11, OsRng.next_u64(), false));
    txn.commit();

    let start = Instant::now();
    let mut task = test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&test.db, Some(11));
    assert!(
      start.elapsed() < Duration::from_secs(1),
      "no-events blocks should not sleep, took {:?}",
      start.elapsed()
    );
  }
}

#[tokio::test]
async fn does_not_regress_and_skips_if_not_a_later_block() {
  let mut test = DelayTest::default();

  // Does not regress
  {
    {
      let mut txn = test.db.txn();
      CosignedBlocks::send(&mut txn, &(1, now_secs(), true));
      CosignedBlocks::send(&mut txn, &(2, now_secs(), true));

      // Sent out of order below
      CosignedBlocks::send(&mut txn, &(4, now_secs(), true));
      // 3 will be skipped after 4 was processed
      CosignedBlocks::send(&mut txn, &(3, now_secs(), true));

      txn.commit();
    }

    let mut task = test.task();
    // returns made_progress as true
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&test.db, Some(4));
  }

  // Skip if not a later block
  {
    {
      let mut txn = test.db.txn();
      // Sends the same previous block number
      CosignedBlocks::send(&mut txn, &(4, now_secs(), true));
      txn.commit();
    }

    let mut task = test.task();
    // No progress was made since the same block number was also skipped,
    // made_progress returns false
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
    verify_db_invariants(&test.db, Some(4));
  }
}

#[tokio::test]
async fn respects_acknowledgement_delay() {
  let mut test = DelayTest::default();
  let block_number = OsRng.next_u64();

  let now = now_secs();
  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(block_number, now, true));
    txn.commit();
  }

  let mut task = test.task();

  // Run the task in the background (it will sleep internally for ACKNOWLEDGEMENT_DELAY)
  let task_handle = tokio::spawn(async move { task.run_iteration().await });

  // Well before ACKNOWLEDGEMENT_DELAY, the block must not be acknowledged
  tokio::time::sleep(Duration::from_secs(ACKNOWLEDGEMENT_DELAY.as_secs().saturating_sub(2))).await;
  assert!(LatestCosignedBlockNumber::get(&test.db).is_none());

  // Wait for the task to complete
  let made_progress = task_handle.await.unwrap().unwrap();
  assert!(made_progress);

  // Block is now finalized
  verify_db_invariants(&test.db, Some(block_number));

  // The elapsed time must be at least ACKNOWLEDGEMENT_DELAY
  let new_now = now_secs();
  assert!(
    Duration::from_secs(new_now) >= (Duration::from_secs(now) + ACKNOWLEDGEMENT_DELAY),
    "completed in {:?}, expected at least {ACKNOWLEDGEMENT_DELAY:?}",
    new_now - now,
  );
}
