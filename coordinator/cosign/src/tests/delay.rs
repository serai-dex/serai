use std::time::Duration;

use crate::{
  LatestCosignedBlockNumber,
  delay::{ACKNOWLEDGEMENT_DELAY, CosignDelayTask, now_timestamp},
  evaluator::CosignedBlocks,
  tests::Test,
};

fn now_secs() -> u64 {
  now_timestamp().as_secs()
}

use serai_db::{Db as _, DbTxn as _};
use serai_task::ContinuallyRan;

impl Test {
  fn into_delay_task(&self) -> impl ContinuallyRan + 'static {
    CosignDelayTask { db: self.db.clone() }
  }

  // Assert CosignedBlocks queue items have been consumed after task run
  fn assert_queue_is_empty(&self) {
    assert!(CosignedBlocks::peek(&self.db).is_none(), "expected queue to be empty");
  }

  fn assert_queue_is_not_empty(&self) {
    assert!(CosignedBlocks::peek(&self.db).is_some(), "expected queue to not be empty");
  }

  // Assert LatestCosignedBlockNumber db points to latest block number after task run
  fn assert_latest_cosigned_block_number_is_expected(&self, block_number: Option<u64>) {
    assert_eq!(LatestCosignedBlockNumber::get(&self.db), block_number);
  }

  // Assert everything that changed or should have changed after a task iteration run
  fn assert_task_iteration_returns(&self, latest_cosigned_block_number: Option<u64>) {
    self.assert_latest_cosigned_block_number_is_expected(latest_cosigned_block_number);
    self.assert_queue_is_empty();
  }

  // Assert everything that changed or should have changed after a task iteration failure
  fn assert_task_iteration_fails(&self, latest_cosigned_block_number: Option<u64>) {
    self.assert_latest_cosigned_block_number_is_expected(latest_cosigned_block_number);
    self.assert_queue_is_not_empty();
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
    CosignedBlocks::send(&mut txn, &(0u64, now_secs()));
    txn.commit();
  }

  let mut task = test.into_delay_task();

  // let already_cosigned = LatestCosignedBlockNumber::get(&self.db).unwrap_or(0);
  // the already_cosigned block number always defaults to 0, so "genesis"
  // is always considered cosigned, made_progress returns false
  Test::assert_task_run_and_check_progress(&mut task, false).await;
}

#[tokio::test]
async fn delay_task_updates_latest_cosigned_block_number() {
  let mut test = Test::new();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(0u64, now_secs()));
    CosignedBlocks::send(&mut txn, &(1u64, now_secs()));
    CosignedBlocks::send(&mut txn, &(2u64, now_secs()));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;
  test.assert_task_iteration_returns(Some(2u64));
}

#[tokio::test]
async fn delay_task_does_not_regress_and_skips_if_not_a_later_block() {
  let mut test = Test::new();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, now_secs()));
    CosignedBlocks::send(&mut txn, &(2u64, now_secs()));

    // Sent out of order below
    CosignedBlocks::send(&mut txn, &(4u64, now_secs()));
    CosignedBlocks::send(&mut txn, &(3u64, now_secs()));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  // Queue order: 1, 2, 4, 3
  // Block 1, 2 and 4 processed, block 3 skipped (3 < 4)

  // This won't actually happen but it needs to be tested that it does what it is
  // meant to do, which is that if we've already acknowledged a later block, consume and skip
  test.assert_task_iteration_returns(Some(4u64));

  {
    let mut txn = test.db.txn();
    // Sends the same previous block number
    CosignedBlocks::send(&mut txn, &(4u64, now_secs()));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  // No progress following the previously set LatestCosignedBlockNumber was made,
  // made_progress returns false
  Test::assert_task_run_and_check_progress(&mut task, false).await;
  test.assert_task_iteration_returns(Some(4u64));

  {
    let mut txn = test.db.txn();
    // Sends the same previous block number
    CosignedBlocks::send(&mut txn, &(4u64, now_secs()));
    // This time ensure progress is made beyond 4
    CosignedBlocks::send(&mut txn, &(5u64, now_secs()));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  // Had a duplicate, but made 1 block worth of progress
  // made_progress returns true
  Test::assert_task_run_and_check_progress(&mut task, true).await;
  test.assert_task_iteration_returns(Some(5u64));
}

#[tokio::test]
async fn delay_task_does_not_ack_before_acknowledgement_delay() {
  let mut test = Test::new();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, now_secs()));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  let handle = tokio::spawn(async move { task.run_iteration().await.unwrap() });

  // Give the task a moment to start and reach the sleep
  tokio::time::sleep(Duration::from_millis(50)).await;

  // Still nothing is returned
  test.assert_latest_cosigned_block_number_is_expected(None);

  // Sleep for most of (but not all) the acknowledgement delay
  tokio::time::sleep(ACKNOWLEDGEMENT_DELAY - Duration::from_secs(1)).await;

  // Still nothing is returned
  test.assert_latest_cosigned_block_number_is_expected(None);

  // Wait for the task to actually complete
  let result = handle.await.unwrap();
  assert_eq!(result, true);

  // Now has a result
  test.assert_task_iteration_returns(Some(1u64));
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
  // Since 0 as timestamp will always be an older date than the current time as timestamp
  // and since the ACK time is considered to be passed, there is no sleep time to do
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  test.assert_task_iteration_returns(Some(1u64));
}

#[tokio::test]
async fn delay_task_with_max_timestamp_returns_error() {
  let mut test = Test::new();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(0u64, now_secs()));
    CosignedBlocks::send(&mut txn, &(1u64, now_secs()));
    CosignedBlocks::send(&mut txn, &(2u64, u64::MAX));
    CosignedBlocks::send(&mut txn, &(3u64, now_secs()));
    txn.commit();
  }

  let mut task = test.into_delay_task();

  // When timestamp is u64::MAX, adding ACKNOWLEDGEMENT_DELAY would overflow
  // The task should return an error instead of panicking
  Test::assert_task_failed(&mut task, "overflow").await;

  test.assert_task_iteration_fails(Some(1u64));
}

#[tokio::test]
async fn delay_task_with_far_future_timestamp_hangs() {
  // A timestamp far in the future (but not MAX to avoid overflow)
  // will cause the task to sleep for an extremely long time
  let mut test = Test::new();

  {
    let mut txn = test.db.txn();
    // Use timestamp 0 for blocks 0 and 1 so they process immediately
    // (time_valid = 0 + ACKNOWLEDGEMENT_DELAY is already in the past)
    CosignedBlocks::send(&mut txn, &(0u64, 0u64));
    CosignedBlocks::send(&mut txn, &(1u64, 0u64));

    let far_future = now_secs() + 1_000_000;
    CosignedBlocks::send(&mut txn, &(2u64, far_future));

    CosignedBlocks::send(&mut txn, &(3u64, 0u64));
    txn.commit();
  }

  let mut task = test.into_delay_task();

  // Use a timeout to prevent the test from hanging forever
  let result = tokio::time::timeout(Duration::from_millis(100), task.run_iteration()).await;

  assert!(result.is_err(), "Expected timeout, but task completed");

  test.assert_task_iteration_fails(Some(1u64));
}

#[tokio::test]
async fn delay_task_increasing_blocks_with_decreasing_timestamps() {
  let mut test = Test::new();
  let base_time = now_secs();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, base_time + 2));
    CosignedBlocks::send(&mut txn, &(2u64, base_time + 1));
    CosignedBlocks::send(&mut txn, &(3u64, base_time));
    txn.commit();
  }

  let mut task = test.into_delay_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  // nothing unusual happens, the task follow block numbers
  // timestamps could be out of order
  test.assert_task_iteration_returns(Some(3u64));
}
