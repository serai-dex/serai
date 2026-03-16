use std::time::{Duration, Instant};

use rand::RngCore;
use rand_core::OsRng;
use serai_task::ContinuallyRan;

use crate::{
  LatestAcknowledgedBlock,
  delay::{ACKNOWLEDGEMENT_DELAY, CosignDelayTask, now_timestamp},
  evaluator::CosignedBlocks,
  tests::{IntoTask, TaskTest},
};

use serai_db::{Db as _, DbTxn as _, MemDb};

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

  fn into_task(&self) -> Self::Task {
    CosignDelayTask { db: self.db.clone() }
  }
}

impl DelayTest {
  pub fn new() -> (Self, Instant) {
    let start = std::time::Instant::now();
    (Self::default(), start)
  }

  async fn assert_task_iteration_completes_with(&self, latest_acknowledged_block: u64) {
    use serai_env::log::debug;
    let actual = LatestAcknowledgedBlock::get(&self.db);
    let cosigned_pending = CosignedBlocks::peek(&self.db).is_some();
    debug!("LatestAcknowledgedBlock: {actual:?} (expected: Some({latest_acknowledged_block}))");
    debug!("CosignedBlocks pending: {cosigned_pending}");
    assert_eq!(actual, Some(latest_acknowledged_block));
    assert!(!cosigned_pending, "CosignedBlocks queue items should have been consumed");
  }
}

#[tokio::test]
async fn returns_false_with_no_messages() {
  serai_env::init_logger();
  let test = DelayTest::default();
  let mut task = test.into_task();

  TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;

  assert_eq!(LatestAcknowledgedBlock::get(&test.db), None);
  assert_eq!(CosignedBlocks::peek(&test.db), None);
}

#[tokio::test]
async fn updates_latest_acknowledged_block_after_ack_delay() {
  let (mut test, start) = DelayTest::new();

  {
    let mut txn = test.db.txn();
    // blocks with the same timestamps
    // nothing unusual happens, the task follow block numbers
    let now = now_secs();
    CosignedBlocks::send(&mut txn, &(0, now));
    CosignedBlocks::send(&mut txn, &(1, now));
    CosignedBlocks::send(&mut txn, &(2, now));
    txn.commit();
  }

  let mut task = test.into_task();

  TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
  test.assert_task_iteration_completes_with(2).await;

  serai_env::log::info!("Blocks 0-2 processed after {:?}", start.elapsed());

  {
    let mut txn = test.db.txn();
    // timestamps out of order
    // nothing unusual happens, the task stil follows block numbers
    let now = now_secs();
    CosignedBlocks::send(&mut txn, &(3, now));
    CosignedBlocks::send(&mut txn, &(4, now - 1));
    CosignedBlocks::send(&mut txn, &(5, now - 2));
    txn.commit();
  }

  TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
  test.assert_task_iteration_completes_with(5).await;

  serai_env::log::info!("Blocks 3-5 processed after {:?}", start.elapsed());

  {
    let mut txn = test.db.txn();
    // timestamps increasing in order
    // nothing unusual happens, the task stil follows block numbers
    let now = now_secs();
    CosignedBlocks::send(&mut txn, &(6, now));
    CosignedBlocks::send(&mut txn, &(7, now + 1));
    CosignedBlocks::send(&mut txn, &(8, now + 2));
    txn.commit();
  }

  TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
  test.assert_task_iteration_completes_with(8).await;

  serai_env::log::info!("Blocks 6-8 processed after {:?}", start.elapsed());
}

#[tokio::test]
async fn does_not_regress_and_skips_if_not_a_later_block() {
  serai_env::init_logger();
  let mut test = DelayTest::default();

  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(1, now_secs()));
    CosignedBlocks::send(&mut txn, &(2, now_secs()));

    // Sent out of order below
    CosignedBlocks::send(&mut txn, &(4, now_secs()));
    // 3 will be skipped after 4 was processed
    CosignedBlocks::send(&mut txn, &(3, now_secs()));

    txn.commit();
  }

  let mut task = test.into_task();
  // returns made_progress as true
  TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

  // This is unlikely to actually happen in practice but it needs to be tested that it does what it is
  // meant to do, which is that if we've already acknowledged a later block, consume and skip
  test.assert_task_iteration_completes_with(4).await;

  {
    let mut txn = test.db.txn();
    // Sends the same previous block number
    CosignedBlocks::send(&mut txn, &(4, now_secs()));
    txn.commit();
  }

  let mut task = test.into_task();

  // No progress was made since the same block number was skipped,
  // made_progress returns false
  TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
  test.assert_task_iteration_completes_with(4).await;
}

#[tokio::test]
async fn respects_acknowledgement_delay() {
  serai_env::init_logger();
  let mut test = DelayTest::default();
  let block_number = OsRng.next_u64();

  let now = now_secs();
  {
    let mut txn = test.db.txn();
    CosignedBlocks::send(&mut txn, &(block_number, now));
    txn.commit();
  }

  let start = Instant::now();
  let mut task = test.into_task();

  // Run the task in the background (it will sleep internally for ACKNOWLEDGEMENT_DELAY)
  let task_handle = tokio::spawn(async move { task.run_iteration().await });

  // Well before ACKNOWLEDGEMENT_DELAY, the block must not be acknowledged
  tokio::time::sleep(Duration::from_secs(ACKNOWLEDGEMENT_DELAY.as_secs().saturating_sub(2))).await;
  assert!(LatestAcknowledgedBlock::get(&test.db).is_none());

  // Wait for the task to complete
  let made_progress = task_handle.await.unwrap().unwrap();
  assert!(made_progress);

  // Block is now acknowledged
  assert_eq!(LatestAcknowledgedBlock::get(&test.db), Some(block_number));

  // The elapsed time must be at least ACKNOWLEDGEMENT_DELAY
  let elapsed = start.elapsed();
  assert!(
    elapsed >= ACKNOWLEDGEMENT_DELAY,
    "completed in {elapsed:?}, expected at least {ACKNOWLEDGEMENT_DELAY:?}"
  );
}
