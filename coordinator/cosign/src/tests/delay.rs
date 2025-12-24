use std::time::{Duration, SystemTime};

use crate::{
  LatestCosignedBlockNumber, delay::ACKNOWLEDGEMENT_DELAY, evaluator::CosignedBlocks, tests::Test,
};

use serai_db::{Db as _, DbTxn as _};
use serai_task::ContinuallyRan;

fn now_timestamp() -> u64 {
  SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs()
}

impl Test {
  // Assert CosignedBlocks queue items have been consumed after task run
  fn assert_queue_empty(&self) {
    assert!(CosignedBlocks::peek(&self.db).is_none(), "expected queue to be empty");
  }

  // Assert LatestCosignedBlockNumber db points to latest block number after task run
  fn assert_latest_cosigned_block_number(&self, block_number: Option<u64>) {
    assert_eq!(LatestCosignedBlockNumber::get(&self.db), block_number);
  }

  // Assert everything that changed or should have changed after a task iteration run
  fn assert_task_iteration(&self, latest_cosigned_block_number: Option<u64>) {
    self.assert_latest_cosigned_block_number(latest_cosigned_block_number);
    self.assert_queue_empty();
  }
}

#[tokio::test]
async fn delay_task_returns_false_with_no_messages() {
  let mut task = Test::new().into_delay_task();
  Test::assert_task_run_and_check_progress(&mut task, false).await;
}

#[tokio::test]
async fn delay_task_returns_false_with_genesis_block() {
  let mut test = Test::new();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(0u64, now_timestamp()));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  Test::assert_task_run_and_check_progress(&mut task, false).await;
}

#[tokio::test]
async fn delay_task_updates_latest_cosigned_block_number() {
  let mut test = Test::new();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, now_timestamp()));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  test.assert_task_iteration(Some(1u64));
}

#[tokio::test]
async fn delay_task_drains_multiple_messages_in_one_iteration() {
  let mut test = Test::new();
  let now = now_timestamp();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, now));
    CosignedBlocks::send(&mut txn, &(2u64, now));
    CosignedBlocks::send(&mut txn, &(3u64, now));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  test.assert_task_iteration(Some(3u64));
}

#[tokio::test]
async fn delay_task_does_not_regress_and_skips_wait_for_stale_messages() {
  let mut test = Test::new();
  let now = now_timestamp();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, now));
    CosignedBlocks::send(&mut txn, &(2u64, now));
    CosignedBlocks::send(&mut txn, &(4u64, now));
    txn.commit();
  }

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(3u64, now));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  // Queue order: 1, 2, 4, 3
  // Block 1 processed (1 > 0), Block 2 processed (2 > 1),
  // Block 4 processed (4 > 2), Block 3 skipped (3 <= 4)
  test.assert_task_iteration(Some(4u64));
}

#[tokio::test]
async fn delay_task_does_not_ack_before_acknowledgement_delay() {
  let mut test = Test::new();
  let now = now_timestamp();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, now));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  let handle = tokio::spawn(async move { task.run_iteration().await.unwrap() });

  // Give the task a moment to start and reach the sleep
  tokio::time::sleep(Duration::from_millis(50)).await;
  test.assert_latest_cosigned_block_number(None);

  // Sleep for most of (but not all) the acknowledgement delay - should still not be set
  tokio::time::sleep(ACKNOWLEDGEMENT_DELAY - Duration::from_secs(1)).await;
  test.assert_latest_cosigned_block_number(None);

  // Wait for the task to complete
  let result = handle.await.unwrap();
  assert_eq!(result, true);

  test.assert_task_iteration(Some(1u64));
}

#[tokio::test]
async fn delay_task_with_zero_timestamp_processes_immediately() {
  let mut test = Test::new();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, 0u64));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  // This should complete immediately without sleeping
  // Since now > 0 + ACKNOWLEDGEMENT_DELAY,
  // time_valid < now (already valid), so no sleep occurs
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  test.assert_task_iteration(Some(1u64));
}

#[tokio::test]
async fn delay_task_with_max_timestamp_returns_error() {
  let mut test = Test::new();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, u64::MAX));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  let result = task.run_iteration().await;

  // When timestamp is u64::MAX, adding ACKNOWLEDGEMENT_DELAY would overflow
  // The task should return an error instead of panicking
  assert!(result.is_err());
  assert!(result.unwrap_err().contains("overflow"));

  // The block should not have been acknowledged
  test.assert_task_iteration(None);
}

#[tokio::test]
async fn delay_task_with_far_future_timestamp_hangs() {
  // A timestamp far in the future (but not MAX to avoid overflow)
  // will cause the task to sleep for an extremely long time
  let mut test = Test::new();
  let far_future = now_timestamp() + 1_000_000;

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, far_future));
    txn.commit();
  }

  let mut task = test.into_delay_task();

  // Use a timeout to prevent the test from hanging forever
  let result = tokio::time::timeout(Duration::from_millis(100), task.run_iteration()).await;

  assert!(result.is_err(), "Expected timeout, but task completed");

  // The block should not have been acknowledged since we timed out
  test.assert_task_iteration(None);
}

#[tokio::test]
async fn delay_task_increasing_blocks_with_increasing_timestamps() {
  let mut test = Test::new();
  let base_time = now_timestamp();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, base_time));
    CosignedBlocks::send(&mut txn, &(2u64, base_time + 1));
    CosignedBlocks::send(&mut txn, &(3u64, base_time + 2));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  test.assert_task_iteration(Some(3u64));
}

#[tokio::test]
async fn delay_task_increasing_blocks_with_decreasing_timestamps() {
  // This simulates a scenario where later blocks were evaluated earlier
  // (e.g., due to clock skew)
  let mut test = Test::new();
  let base_time = now_timestamp();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, base_time + 2));
    CosignedBlocks::send(&mut txn, &(2u64, base_time + 1));
    CosignedBlocks::send(&mut txn, &(3u64, base_time));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  // All blocks should still be processed in order, ending with block 3
  // Even though block 3 has an earlier timestamp, it processes after block 1 and 2
  test.assert_task_iteration(Some(3u64));
}
