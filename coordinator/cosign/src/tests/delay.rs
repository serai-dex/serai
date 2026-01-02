use std::time::Duration;

use crate::{
  LatestCosignedBlockNumber,
  delay::{ACKNOWLEDGEMENT_DELAY, CosignDelayTask, now_timestamp},
  evaluator::CosignedBlocks,
  tests::{IntoTask, Test},
};

use serai_db::{Db as _, DbTxn as _, MemDb};

fn now_secs() -> u64 {
  now_timestamp().as_secs()
}

fn past_timestamp() -> u64 {
  // A timestamp old enough that time_valid is already passed
  now_secs().saturating_sub(2 * ACKNOWLEDGEMENT_DELAY.as_secs())
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

  fn into_task(&self) -> Self::Task {
    CosignDelayTask { db: self.db.clone() }
  }
}

impl DelayTest {
  fn assert_queue_is_empty(&self) {
    assert_eq!(CosignedBlocks::peek(&self.db), None);
  }

  fn assert_queue_is_not_empty(&self) {
    assert_eq!(CosignedBlocks::peek(&self.db).is_some(), true);
  }

  fn assert_latest_cosigned_block_number_is_expected(&self, block_number: Option<u64>) {
    assert_eq!(LatestCosignedBlockNumber::get(&self.db), block_number);
  }

  // Assert everything that changed or should have changed after a task iteration run
  fn assert_task_iteration_completes_with(&self, latest_cosigned_block_number: u64) {
    // Assert LatestCosignedBlockNumber db points to latest block number after task run
    self.assert_latest_cosigned_block_number_is_expected(Some(latest_cosigned_block_number));
    // Assert CosignedBlocks queue items have been consumed after task run
    self.assert_queue_is_empty();
  }

  // Assert nothing was added or remains after dbs are expected to be cleared
  fn assert_task_iteration_db_is_clear(&self) {
    self.assert_latest_cosigned_block_number_is_expected(None);
    self.assert_queue_is_empty();
  }

  fn assert_task_iteration_fails(&self, latest_cosigned_block_number: Option<u64>) {
    self.assert_latest_cosigned_block_number_is_expected(latest_cosigned_block_number);
    self.assert_queue_is_not_empty();
  }
}

#[tokio::test]
async fn delay_task_returns_false_with_no_messages() {
  let test = DelayTest::default();
  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, false).await;
  test.assert_task_iteration_db_is_clear();
}

#[tokio::test]
async fn delay_task_returns_false_with_genesis_block() {
  let mut test = DelayTest::default();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(0u64, now_secs()));
    txn.commit();
  }

  let mut task = test.into_task();

  // let already_cosigned = LatestCosignedBlockNumber::get(&self.db).unwrap_or(0);
  // the already_cosigned block number always defaults to 0, so "genesis"
  // is always considered cosigned, made_progress returns false
  Test::assert_task_run_iteration_and_check_progress(&mut task, false).await;
  test.assert_task_iteration_db_is_clear();
}

#[tokio::test]
async fn delay_task_updates_latest_cosigned_block_number() {
  let mut test = DelayTest::default();

  {
    let mut txn = test.db.txn();
    // blocks with the same timestamps
    // nothing unusual happens, the task follow block numbers
    let past = past_timestamp();
    CosignedBlocks::send(&mut txn, &(0u64, past));
    CosignedBlocks::send(&mut txn, &(1u64, past));
    CosignedBlocks::send(&mut txn, &(2u64, past));
    txn.commit();
  }

  let mut task = test.into_task();

  // returns made_progress as true
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;
  // confirmed the last block as 2
  test.assert_task_iteration_completes_with(2u64);

  let mut test = DelayTest::default();

  {
    let mut txn = test.db.txn();
    // timestamps out of order
    // nothing unusual happens, the task stil follows block numbers
    let past = past_timestamp();
    CosignedBlocks::send(&mut txn, &(3u64, past));
    CosignedBlocks::send(&mut txn, &(4u64, past - 1));
    CosignedBlocks::send(&mut txn, &(5u64, past - 2));
    txn.commit();
  }

  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;
  test.assert_task_iteration_completes_with(5u64);

  // Test with increasing timestamps (all in the past, so they process immediately)
  let mut test = DelayTest::default();

  {
    let mut txn = test.db.txn();
    // timestamps increasing in order
    // nothing unusual happens, the task stil follows block numbers
    let past = past_timestamp();
    CosignedBlocks::send(&mut txn, &(6u64, past));
    CosignedBlocks::send(&mut txn, &(7u64, past + 1));
    CosignedBlocks::send(&mut txn, &(8u64, past + 2));
    txn.commit();
  }

  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;
  test.assert_task_iteration_completes_with(8u64);
}

#[tokio::test]
async fn delay_task_does_not_regress_and_skips_if_not_a_later_block() {
  let mut test = DelayTest::default();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, past_timestamp()));
    CosignedBlocks::send(&mut txn, &(2u64, past_timestamp()));

    // Sent out of order below
    CosignedBlocks::send(&mut txn, &(4u64, past_timestamp()));
    CosignedBlocks::send(&mut txn, &(3u64, past_timestamp()));

    txn.commit();
  }

  let mut task = test.into_task();
  // returns made_progress as true
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

  // Queue order: 1, 2, 4, 3
  // Block 1, 2 and 4 processed, block 3 skipped

  // This is unlikely to actually happen in practice but it needs to be tested that it does what it is
  // meant to do, which is that if we've already acknowledged a later block, consume and skip
  test.assert_task_iteration_completes_with(4u64);

  {
    let mut txn = test.db.txn();
    // Sends the same previous block number
    CosignedBlocks::send(&mut txn, &(4u64, past_timestamp()));
    txn.commit();
  }

  let mut task = test.into_task();

  // No progress was made since the same block number was skipped,
  // made_progress returns false
  Test::assert_task_run_iteration_and_check_progress(&mut task, false).await;
  test.assert_task_iteration_completes_with(4u64);

  {
    let mut txn = test.db.txn();
    // Sends the same previous block number
    CosignedBlocks::send(&mut txn, &(4u64, past_timestamp()));
    // This time ensure progress is made beyond 4
    CosignedBlocks::send(&mut txn, &(5u64, past_timestamp()));
    txn.commit();
  }

  let mut task = test.into_task();
  // Had a duplicate, but made 1 block worth of progress
  // made_progress returns true
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;
  // confirmed the last block as 5
  test.assert_task_iteration_completes_with(5u64);
}

#[tokio::test]
async fn delay_task_does_not_ack_before_acknowledgement_delay() {
  let mut test = DelayTest::default();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, now_secs()));
    txn.commit();
  }

  let mut task = test.into_task();

  // First iteration returns early - not ready yet
  Test::assert_task_run_iteration_and_check_progress(&mut task, false).await;

  test.assert_latest_cosigned_block_number_is_expected(None);
  test.assert_queue_is_not_empty(); // Message still in queue

  // Wait for the delay to pass
  tokio::time::sleep(ACKNOWLEDGEMENT_DELAY + Duration::from_secs(1)).await;

  // Now iteration should succeed
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;
  test.assert_task_iteration_completes_with(1u64);
}

#[tokio::test]
async fn delay_task_with_zero_timestamp_processes_immediately() {
  let mut test = DelayTest::default();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, 0u64));
    txn.commit();
  }

  let mut task = test.into_task();

  // This should complete immediately without sleeping
  // Since 0 as timestamp will always be an older date than the current time as timestamp
  // and since the ACK time is considered to be passed, there is no sleep time to do
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

  test.assert_task_iteration_completes_with(1u64);
}

#[tokio::test]
async fn delay_task_with_max_timestamp_returns_error() {
  let mut test = DelayTest::default();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(0u64, past_timestamp()));
    CosignedBlocks::send(&mut txn, &(1u64, past_timestamp()));
    CosignedBlocks::send(&mut txn, &(2u64, u64::MAX));
    CosignedBlocks::send(&mut txn, &(3u64, past_timestamp()));
    txn.commit();
  }

  let mut task = test.into_task();

  // When timestamp is u64::MAX, adding ACKNOWLEDGEMENT_DELAY would overflow
  // The task should return an error instead of panicking
  Test::assert_task_run_and_failed_with(&mut task, "overflow").await;

  // since returned an error 3u64 should still be in queue
  test.assert_task_iteration_fails(Some(1u64));
}

#[tokio::test]
async fn delay_task_with_far_future_timestamp_returns_early() {
  let mut test = DelayTest::default();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(0u64, past_timestamp()));
    CosignedBlocks::send(&mut txn, &(1u64, past_timestamp()));

    let far_future = now_secs() + 1_000_000;
    CosignedBlocks::send(&mut txn, &(2u64, far_future));

    CosignedBlocks::send(&mut txn, &(3u64, past_timestamp()));
    txn.commit();
  }

  let mut task = test.into_task();

  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

  // It processed blocks 0 and 1, then returned early on block 2
  test.assert_latest_cosigned_block_number_is_expected(Some(1));
  // Block 2,3 stay in queue until the time is valid
  test.assert_queue_is_not_empty();
}
