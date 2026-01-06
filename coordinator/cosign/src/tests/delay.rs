use std::time::{Duration, Instant};

use crate::{
  LatestCosignedBlockNumber,
  delay::{ACKNOWLEDGEMENT_DELAY, CosignDelayTask, now_timestamp},
  evaluator::CosignedBlocks,
  tests::{IntoTask, Test, wait_until},
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
    let _ = env_logger::try_init();
    (Self::default(), start)
  }

  async fn assert_task_iteration_completes_with(&self, latest_cosigned_block_number: u64) {
    wait_until!(LatestCosignedBlockNumber::get(&self.db) => Some(latest_cosigned_block_number));

    // Assert CosignedBlocks queue items have been consumed after task run
    assert_eq!(CosignedBlocks::peek(&self.db), None);
  }
}

#[tokio::test]
async fn delay_task_returns_false_with_no_messages() {
  let test = DelayTest::default();
  let mut task = test.into_task();

  Test::assert_task_run_iteration_and_check_progress(&mut task, false).await;

  assert_eq!(LatestCosignedBlockNumber::get(&test.db), None);
  assert_eq!(CosignedBlocks::peek(&test.db), None);
}

#[tokio::test]
async fn delay_task_updates_latest_cosigned_block_number_after_ack_delay() {
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

  let task = test.into_task();
  let handle = Test::spawn_task_continually_running(task, vec![]);

  test.assert_task_iteration_completes_with(2).await;

  log::info!("Blocks 0-2 processed after {:?}", start.elapsed());

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

  test.assert_task_iteration_completes_with(5).await;

  log::info!("Blocks 3-5 processed after {:?}", start.elapsed());

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

  test.assert_task_iteration_completes_with(8).await;

  log::info!("Blocks 6-8 processed after {:?}", start.elapsed());
}

#[tokio::test]
async fn delay_task_does_not_regress_and_skips_if_not_a_later_block() {
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
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

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
  Test::assert_task_run_iteration_and_check_progress(&mut task, false).await;
  test.assert_task_iteration_completes_with(4).await;
}
