use crate::LatestCosignedBlockNumber;
use crate::delay::{ACKNOWLEDGEMENT_DELAY, CosignDelayTask};
use std::{
  sync::OnceLock,
  time::{Duration, SystemTime},
};

use serai_db::*;
use serai_task::ContinuallyRan;

use crate::evaluator::CosignedBlocks;

use serai_db::{Db as _, MemDb};

#[tokio::test]
async fn delay_task_returns_false_with_no_messages() {
  let db = MemDb::new();
  let mut task = CosignDelayTask { db };
  assert_eq!(task.run_iteration().await.unwrap(), false);
}

#[tokio::test]
async fn delay_task_updates_latest_cosigned_block_number() {
  let mut db = MemDb::new();

  {
    let mut txn = db.txn();
    CosignedBlocks::send(&mut txn, &(7u64, 0u64));
    txn.commit();
  }

  let mut task = CosignDelayTask { db: db.clone() };
  assert_eq!(task.run_iteration().await.unwrap(), true);
  assert_eq!(LatestCosignedBlockNumber::get(&db), Some(7u64));
}

#[tokio::test]
async fn delay_task_drains_multiple_messages_in_one_iteration() {
  let mut db = MemDb::new();

  {
    let mut txn = db.txn();
    CosignedBlocks::send(&mut txn, &(1u64, 0u64));
    CosignedBlocks::send(&mut txn, &(2u64, 0u64));
    CosignedBlocks::send(&mut txn, &(3u64, 0u64));
    txn.commit();
  }

  let mut task = CosignDelayTask { db: db.clone() };
  assert_eq!(task.run_iteration().await.unwrap(), true);
  assert_eq!(LatestCosignedBlockNumber::get(&db), Some(3u64));
  assert!(CosignedBlocks::peek(&db).is_none());
}

#[tokio::test(start_paused = true)]
async fn delay_task_does_not_regress_and_skips_wait_for_stale_messages() {
  let mut db = MemDb::new();

  {
    let mut txn = db.txn();
    LatestCosignedBlockNumber::set(&mut txn, &10u64);
    txn.commit();
  }

  let now_secs =
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs();

  {
    let mut txn = db.txn();
    CosignedBlocks::send(&mut txn, &(9u64, now_secs));
    txn.commit();
  }

  let mut task = CosignDelayTask { db: db.clone() };
  let handle = tokio::spawn(async move { task.run_iteration().await.unwrap() });
  tokio::task::yield_now().await;

  assert_eq!(handle.await.unwrap(), true);
  assert_eq!(LatestCosignedBlockNumber::get(&db), Some(10u64));
  assert!(CosignedBlocks::peek(&db).is_none());
}

#[tokio::test(start_paused = true)]
async fn delay_task_does_not_ack_before_acknowledgement_delay() {
  let mut db = MemDb::new();

  let now_secs =
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or(Duration::ZERO).as_secs();

  {
    let mut txn = db.txn();
    CosignedBlocks::send(&mut txn, &(7u64, now_secs));
    txn.commit();
  }

  let mut task = CosignDelayTask { db: db.clone() };
  let handle = tokio::spawn(async move { task.run_iteration().await.unwrap() });

  tokio::task::yield_now().await;
  assert_eq!(LatestCosignedBlockNumber::get(&db), None);

  tokio::time::advance(ACKNOWLEDGEMENT_DELAY - Duration::from_secs(2)).await;
  tokio::task::yield_now().await;
  assert_eq!(LatestCosignedBlockNumber::get(&db), None);

  tokio::time::advance(Duration::from_secs(4)).await;
  tokio::task::yield_now().await;

  assert_eq!(handle.await.unwrap(), true);
  assert_eq!(LatestCosignedBlockNumber::get(&db), Some(7u64));
}
