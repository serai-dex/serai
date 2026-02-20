use std::{
  collections::HashMap,
  sync::atomic::Ordering,
  time::{Duration, Instant},
};

use serai_cosign_types::SignedCosign;
use serai_db::{Db as _, DbTxn, MemDb};
use serai_client_serai::abi::primitives::{
  BlockHash,
  crypto::Public,
  network_id::ExternalNetworkId,
  validator_sets::{ExternalValidatorSet, Session},
};

use serai_task::ContinuallyRan;

use crate::{
  Cosign, GlobalSession, HasEvents, NetworksLatestCosignedBlock,
  evaluator::{
    CosignEvaluatorTask, CosignedBlocks, CurrentlyEvaluatedGlobalSession, REQUEST_COSIGNS_SPACING,
  },
  intend::{BlockEventData, BlockEvents, GlobalSessionsChannel},
  tests::{IntoTask, TaskTest, TestRequest},
};

pub(crate) struct EvaluatorTest {
  pub(crate) db: MemDb,
}

impl Default for EvaluatorTest {
  fn default() -> Self {
    Self { db: MemDb::new() }
  }
}

impl IntoTask for EvaluatorTest {
  type Task = CosignEvaluatorTask<MemDb, TestRequest>;

  fn into_task(&self) -> Self::Task {
    let (request, _calls) = TestRequest::new(false);
    CosignEvaluatorTask { db: self.db.clone(), request, last_request_for_cosigns: Instant::now() }
  }
}

impl EvaluatorTest {
  fn assert_no_currently_evaluated_global_session(&self) {
    assert_eq!(CurrentlyEvaluatedGlobalSession::get(&self.db).is_none(), true);
  }

  /// Asserts that cosigned blocks from start_block to end_block (inclusive) are present in order.
  fn assert_cosigned_blocks_range(&mut self, start_block: u64, end_block: u64) {
    let mut txn = self.db.txn();
    for expected_block in start_block ..= end_block {
      let (block_number, _time) = CosignedBlocks::try_recv(&mut txn)
        .unwrap_or_else(|| panic!("expected cosigned block {expected_block}"));
      assert_eq!(block_number, expected_block, "cosigned block mismatch");
    }
    assert!(CosignedBlocks::try_recv(&mut txn).is_none(), "unexpected extra cosigned block");
    txn.commit();
  }

  fn assert_no_cosigned_blocks(&self) {
    assert_eq!(CosignedBlocks::peek(&self.db).is_none(), true);
  }

  fn assert_no_global_sessions_channel(&self) {
    assert_eq!(GlobalSessionsChannel::peek(&self.db).is_none(), true);
  }

  fn assert_has_global_sessions_channel(&self) {
    assert_eq!(GlobalSessionsChannel::peek(&self.db).is_some(), true);
  }

  fn assert_no_block_events(&self) {
    assert_eq!(BlockEvents::peek(&self.db).is_none(), true);
  }

  fn assert_has_block_events(&self) {
    assert_eq!(BlockEvents::peek(&self.db).is_some(), true);
  }

  /// Asserts that all evaluator DB entries are cleared (return None or are empty).
  /// This is useful for verifying initial state or that cleanup worked correctly.
  fn assert_evaluator_db_is_clear(&self) {
    self.assert_no_currently_evaluated_global_session();
    self.assert_no_cosigned_blocks();
    self.assert_no_global_sessions_channel();
    self.assert_no_block_events();
  }

  fn assert_task_iteration_completed(&mut self, start_block: u64, end_block: u64) {
    self.assert_no_global_sessions_channel();
    self.assert_no_block_events();
    self.assert_cosigned_blocks_range(start_block, end_block);
  }

  const GLOBAL_SESSION: [u8; 32] = [1u8; 32];

  /// Initializes a global session with the hardcoded test ID and the given start block number.
  /// Returns the global session ID for use in tests that need it.
  fn init_global_session(&mut self, start_block_number: u64) -> [u8; 32] {
    let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };

    let mut keys = HashMap::new();
    keys.insert(ExternalNetworkId::Bitcoin, Public([1u8; 32]));

    let mut stakes = HashMap::new();
    stakes.insert(ExternalNetworkId::Bitcoin, 1u64);

    let info =
      GlobalSession { start_block_number, sets: vec![set], keys, stakes, total_stake: 1u64 };

    let mut txn = self.db.txn();
    GlobalSessionsChannel::send(&mut txn, &(Self::GLOBAL_SESSION, info));
    txn.commit();

    Self::GLOBAL_SESSION
  }
}

#[tokio::test]
async fn evaluator_task_returns_false_with_no_block_events() {
  let test = EvaluatorTest::default();
  let mut task = test.into_task();
  TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
  test.assert_evaluator_db_is_clear();
}

#[tokio::test]
async fn evaluator_task_processes_blocks_with_no_events() {
  let mut test = EvaluatorTest::default();
  test.init_global_session(0);

  {
    let mut txn = test.db.txn();
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 0, has_events: HasEvents::No });
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 1, has_events: HasEvents::No });
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 2, has_events: HasEvents::No });
    txn.commit();
  }

  let mut task = test.into_task();
  TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
  test.assert_task_iteration_completed(0, 2);
}

#[tokio::test]
async fn evaluator_task_errors_on_notable_events_without_cosign() {
  let mut test = EvaluatorTest::default();
  test.init_global_session(0);

  {
    let mut txn = test.db.txn();
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 0, has_events: HasEvents::No });
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 1, has_events: HasEvents::No });
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 2, has_events: HasEvents::Notable },
    );
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 3, has_events: HasEvents::No });
    txn.commit();
  }

  let mut task = test.into_task();
  TaskTest::assert_task_run_and_failed_with(&mut task, "wasn't yet cosigned").await;
  // When iteration fails, nothing is committed - block events are consumed but CosignedBlocks is empty
  test.assert_no_global_sessions_channel();
  test.assert_has_block_events();

  {
    let mut txn = test.db.txn();
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 1, has_events: HasEvents::No });
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 2, has_events: HasEvents::Notable },
    );
    txn.commit();
  }

  let mut task: CosignEvaluatorTask<MemDb, TestRequest> = test.into_task().into();
  task.last_request_for_cosigns = Instant::now() - Duration::from_secs(5);

  TaskTest::assert_task_run_and_failed_with(&mut task, "wasn't yet cosigned").await;
  test.assert_no_global_sessions_channel();
  test.assert_has_block_events();
}

fn signed_cosign(
  global_session: [u8; 32],
  cosigner: ExternalNetworkId,
  block_number: u64,
) -> SignedCosign {
  SignedCosign {
    cosign: Cosign { global_session, block_number, block_hash: BlockHash([0u8; 32]), cosigner },
    signature: [0u8; 64],
  }
}

#[tokio::test]
async fn evaluator_task_errors_on_notable_events_without_stakes() {
  let mut test = EvaluatorTest::default();

  let global_session = {
    let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };

    let mut keys = HashMap::new();
    keys.insert(ExternalNetworkId::Bitcoin, Public([1u8; 32]));

    let stakes = HashMap::new();

    let info =
      GlobalSession { start_block_number: 0, sets: vec![set], keys, stakes, total_stake: 1u64 };

    let mut txn = test.db.txn();
    GlobalSessionsChannel::send(&mut txn, &(EvaluatorTest::GLOBAL_SESSION, info));
    txn.commit();

    EvaluatorTest::GLOBAL_SESSION
  };

  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      ExternalNetworkId::Bitcoin,
      &signed_cosign(global_session, ExternalNetworkId::Bitcoin, 1),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::Notable },
    );
    txn.commit();
  }

  let mut task = test.into_task();
  TaskTest::assert_task_run_and_failed_with(&mut task, "didn't have its stake").await;
}

#[tokio::test]
async fn evaluator_task_errors_on_non_notable_events_without_cosign() {
  let mut test = EvaluatorTest::default();
  test.init_global_session(0);

  {
    let mut txn = test.db.txn();
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 0, has_events: HasEvents::No });
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 1, has_events: HasEvents::No });
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 2, has_events: HasEvents::NonNotable },
    );
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 3, has_events: HasEvents::No });
    txn.commit();
  }

  let mut task = test.into_task();
  TaskTest::assert_task_run_and_failed_with(&mut task, "wasn't yet cosigned").await;
  // When iteration fails, nothing is committed
  test.assert_no_global_sessions_channel();
  test.assert_has_block_events();

  {
    let mut txn = test.db.txn();
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 1, has_events: HasEvents::No });
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 2, has_events: HasEvents::NonNotable },
    );
    txn.commit();
  }

  let mut task: CosignEvaluatorTask<MemDb, TestRequest> = test.into_task().into();
  task.last_request_for_cosigns = Instant::now() - Duration::from_secs(5);

  TaskTest::assert_task_run_and_failed_with(&mut task, "wasn't yet cosigned").await;
}

#[tokio::test]
async fn evaluator_task_errors_on_request_notable_cosigns_failure() {
  let mut test = EvaluatorTest::default();
  test.init_global_session(0);

  {
    let mut txn = test.db.txn();
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::Notable },
    );
    txn.commit();
  }

  let (request, calls) = TestRequest::new(true);
  let mut task = CosignEvaluatorTask {
    db: test.db.clone(),
    request,
    last_request_for_cosigns: Instant::now() - REQUEST_COSIGNS_SPACING - Duration::from_secs(5),
  };

  TaskTest::assert_task_run_and_failed_with(&mut task, "RequestError").await;
  assert_eq!(calls.load(Ordering::SeqCst), 1, "request_notable_cosigns should have been called");
}

#[tokio::test]
async fn evaluator_task_errors_on_request_non_notable_cosigns_failure() {
  let mut test = EvaluatorTest::default();
  test.init_global_session(0);

  {
    let mut txn = test.db.txn();
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::NonNotable },
    );
    txn.commit();
  }

  let (request, calls) = TestRequest::new(true);
  let mut task = CosignEvaluatorTask {
    db: test.db.clone(),
    request,
    last_request_for_cosigns: Instant::now() - REQUEST_COSIGNS_SPACING - Duration::from_secs(5),
  };

  TaskTest::assert_task_run_and_failed_with(&mut task, "RequestError").await;
  assert_eq!(calls.load(Ordering::SeqCst), 1, "request_notable_cosigns should have been called");
}

#[tokio::test]
async fn evaluator_task_processes_notable_events_when_cosigned() {
  let mut test = EvaluatorTest::default();
  let global_session = test.init_global_session(0);

  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      ExternalNetworkId::Bitcoin,
      &signed_cosign(global_session, ExternalNetworkId::Bitcoin, 1),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::Notable },
    );
    txn.commit();
  }

  let mut task = test.into_task();
  TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

  let (block_number, _time) = CosignedBlocks::peek(&test.db).expect("expected cosigned block");
  assert_eq!(block_number, 1);
}

#[tokio::test]
async fn evaluator_task_non_notable_uses_cached_known_cosign() {
  let mut test = EvaluatorTest::default();
  let global_session = test.init_global_session(0);

  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      ExternalNetworkId::Bitcoin,
      &signed_cosign(global_session, ExternalNetworkId::Bitcoin, 10),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::NonNotable },
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 2, has_events: HasEvents::NonNotable },
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 3, has_events: HasEvents::NonNotable },
    );
    txn.commit();
  }

  let mut task = test.into_task();
  TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

  // All three blocks should be marked as cosigned
  test.assert_cosigned_blocks_range(1, 3);
}

#[tokio::test]
async fn evaluator_task_non_notable_with_cosign_returns_some() {
  let mut test = EvaluatorTest::default();
  let global_session = test.init_global_session(0);

  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      ExternalNetworkId::Bitcoin,
      &signed_cosign(global_session, ExternalNetworkId::Bitcoin, 5),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::NonNotable },
    );
    txn.commit();
  }

  let mut task = test.into_task();
  TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

  test.assert_cosigned_blocks_range(1, 1);
}

#[tokio::test]
async fn evaluator_task_non_notable_cosign_too_low_does_not_add_weight() {
  let mut test = EvaluatorTest::default();
  let global_session = test.init_global_session(0);

  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      ExternalNetworkId::Bitcoin,
      &signed_cosign(global_session, ExternalNetworkId::Bitcoin, 1),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 5, has_events: HasEvents::NonNotable },
    );
    txn.commit();
  }

  let mut task = test.into_task();
  TaskTest::assert_task_run_and_failed_with(&mut task, "wasn't yet cosigned").await;
}

#[tokio::test]
async fn evaluator_task_errors_on_non_notable_events_without_stakes() {
  let mut test = EvaluatorTest::default();

  let global_session = {
    let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };

    let mut keys = HashMap::new();
    keys.insert(ExternalNetworkId::Bitcoin, Public([1u8; 32]));

    let stakes = HashMap::new();

    let info =
      GlobalSession { start_block_number: 0, sets: vec![set], keys, stakes, total_stake: 1u64 };

    let mut txn = test.db.txn();
    GlobalSessionsChannel::send(&mut txn, &(EvaluatorTest::GLOBAL_SESSION, info));
    txn.commit();

    EvaluatorTest::GLOBAL_SESSION
  };

  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      ExternalNetworkId::Bitcoin,
      &signed_cosign(global_session, ExternalNetworkId::Bitcoin, 5),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::NonNotable },
    );
    txn.commit();
  }

  let mut task = test.into_task();
  TaskTest::assert_task_run_and_failed_with(&mut task, "didn't have its stake").await;
}

#[tokio::test]
async fn evaluator_task_non_notable_computes_lowest_common_block() {
  let mut test = EvaluatorTest::default();

  let global_session = {
    let sets = vec![
      ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) },
      ExternalValidatorSet { network: ExternalNetworkId::Ethereum, session: Session(0) },
    ];

    let mut keys = HashMap::new();
    keys.insert(ExternalNetworkId::Bitcoin, Public([1u8; 32]));
    keys.insert(ExternalNetworkId::Ethereum, Public([2u8; 32]));

    let mut stakes = HashMap::new();
    stakes.insert(ExternalNetworkId::Bitcoin, 50u64);
    stakes.insert(ExternalNetworkId::Ethereum, 50u64);

    let info = GlobalSession { start_block_number: 0, sets, keys, stakes, total_stake: 100u64 };

    let mut txn = test.db.txn();
    GlobalSessionsChannel::send(&mut txn, &(EvaluatorTest::GLOBAL_SESSION, info));
    txn.commit();

    EvaluatorTest::GLOBAL_SESSION
  };

  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      ExternalNetworkId::Bitcoin,
      &signed_cosign(global_session, ExternalNetworkId::Bitcoin, 10),
    );
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      ExternalNetworkId::Ethereum,
      &signed_cosign(global_session, ExternalNetworkId::Ethereum, 5),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::NonNotable },
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 2, has_events: HasEvents::NonNotable },
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 3, has_events: HasEvents::NonNotable },
    );
    txn.commit();
  }

  let mut task = test.into_task();
  TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

  test.assert_cosigned_blocks_range(1, 3);
}

#[tokio::test]
#[should_panic(expected = "candidate's start block number ")]
async fn evaluator_task_panics_when_session_starts_after_block() {
  let mut test = EvaluatorTest::default();

  {
    let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };

    let mut keys = HashMap::new();
    keys.insert(ExternalNetworkId::Bitcoin, Public([1u8; 32]));

    let mut stakes = HashMap::new();
    stakes.insert(ExternalNetworkId::Bitcoin, 1u64);

    let info =
      GlobalSession { start_block_number: 10, sets: vec![set], keys, stakes, total_stake: 1u64 };

    let mut txn = test.db.txn();
    CurrentlyEvaluatedGlobalSession::set(&mut txn, &(EvaluatorTest::GLOBAL_SESSION, info));
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 5, has_events: HasEvents::No });
    txn.commit();
  }

  let mut task = test.into_task();
  let _ = task.run_iteration().await;
}

#[tokio::test]
#[should_panic(expected = "currently_evaluated_global_session_strict wasn't called incrementally")]
async fn evaluator_task_panics_when_called_non_incrementally() {
  let mut test = EvaluatorTest::default();

  {
    let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
    let mut keys = HashMap::new();
    keys.insert(ExternalNetworkId::Bitcoin, Public([1u8; 32]));
    let mut stakes = HashMap::new();
    stakes.insert(ExternalNetworkId::Bitcoin, 1u64);
    let info =
      GlobalSession { start_block_number: 0, sets: vec![set], keys, stakes, total_stake: 1u64 };

    let mut txn = test.db.txn();
    GlobalSessionsChannel::send(&mut txn, &([1u8; 32], info));
    txn.commit();
  }

  {
    let set = ExternalValidatorSet { network: ExternalNetworkId::Ethereum, session: Session(0) };
    let mut keys = HashMap::new();
    keys.insert(ExternalNetworkId::Ethereum, Public([2u8; 32]));
    let mut stakes = HashMap::new();
    stakes.insert(ExternalNetworkId::Ethereum, 1u64);
    let info =
      GlobalSession { start_block_number: 5, sets: vec![set], keys, stakes, total_stake: 1u64 };

    let mut txn = test.db.txn();
    GlobalSessionsChannel::send(&mut txn, &([2u8; 32], info));
    txn.commit();
  }

  {
    let mut txn = test.db.txn();
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 10, has_events: HasEvents::No });
    txn.commit();
  }

  let mut task = test.into_task();
  let _ = task.run_iteration().await;
}

#[tokio::test]
async fn evaluator_task_advances_global_session_at_start_block() {
  let mut test = EvaluatorTest::default();

  let session1 = [1u8; 32];
  {
    let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
    let mut keys = HashMap::new();
    keys.insert(ExternalNetworkId::Bitcoin, Public([1u8; 32]));
    let mut stakes = HashMap::new();
    stakes.insert(ExternalNetworkId::Bitcoin, 1u64);
    let info =
      GlobalSession { start_block_number: 0, sets: vec![set], keys, stakes, total_stake: 1u64 };

    let mut txn = test.db.txn();
    GlobalSessionsChannel::send(&mut txn, &(session1, info));
    txn.commit();
  }

  let session2 = [2u8; 32];
  {
    let set = ExternalValidatorSet { network: ExternalNetworkId::Ethereum, session: Session(0) };
    let mut keys = HashMap::new();
    keys.insert(ExternalNetworkId::Ethereum, Public([2u8; 32]));
    let mut stakes = HashMap::new();
    stakes.insert(ExternalNetworkId::Ethereum, 1u64);
    let info =
      GlobalSession { start_block_number: 3, sets: vec![set], keys, stakes, total_stake: 1u64 };

    let mut txn = test.db.txn();
    GlobalSessionsChannel::send(&mut txn, &(session2, info));
    txn.commit();
  }

  {
    let mut txn = test.db.txn();
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 1, has_events: HasEvents::No });
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 2, has_events: HasEvents::No });
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 3, has_events: HasEvents::No });
    txn.commit();
  }

  let mut task = test.into_task();
  TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

  test.assert_cosigned_blocks_range(1, 3);

  let current =
    CurrentlyEvaluatedGlobalSession::get(&test.db).expect("should have current session");
  assert_eq!(current.0, session2, "should have transitioned to session 2");
  assert_eq!(current.1.start_block_number, 3, "session 2 should start at block 3");
}

#[tokio::test]
#[should_panic(expected = "attempt to add with overflow")]
async fn evaluator_task_errors_on_weight_overflow_notable() {
  let mut test = EvaluatorTest::default();

  let global_session = {
    let sets = vec![
      ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) },
      ExternalValidatorSet { network: ExternalNetworkId::Ethereum, session: Session(0) },
    ];

    let mut keys = HashMap::new();
    keys.insert(ExternalNetworkId::Bitcoin, Public([1u8; 32]));
    keys.insert(ExternalNetworkId::Ethereum, Public([2u8; 32]));

    let mut stakes = HashMap::new();
    stakes.insert(ExternalNetworkId::Bitcoin, u64::MAX);
    stakes.insert(ExternalNetworkId::Ethereum, 1u64);

    let info = GlobalSession { start_block_number: 0, sets, keys, stakes, total_stake: u64::MAX };

    let mut txn = test.db.txn();
    GlobalSessionsChannel::send(&mut txn, &(EvaluatorTest::GLOBAL_SESSION, info));
    txn.commit();

    EvaluatorTest::GLOBAL_SESSION
  };

  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      ExternalNetworkId::Bitcoin,
      &signed_cosign(global_session, ExternalNetworkId::Bitcoin, 1),
    );
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      ExternalNetworkId::Ethereum,
      &signed_cosign(global_session, ExternalNetworkId::Ethereum, 1),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::Notable },
    );
    txn.commit();
  }

  let mut task = test.into_task();
  TaskTest::assert_task_run_and_failed_with(&mut task, "weight_cosigned overflow").await;
}

#[tokio::test]
#[should_panic(expected = "attempt to add with overflow")]
async fn evaluator_task_errors_on_weight_overflow_non_notable() {
  let mut test = EvaluatorTest::default();

  let global_session = {
    let sets = vec![
      ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) },
      ExternalValidatorSet { network: ExternalNetworkId::Ethereum, session: Session(0) },
    ];

    let mut keys = HashMap::new();
    keys.insert(ExternalNetworkId::Bitcoin, Public([1u8; 32]));
    keys.insert(ExternalNetworkId::Ethereum, Public([2u8; 32]));

    let mut stakes = HashMap::new();
    stakes.insert(ExternalNetworkId::Bitcoin, u64::MAX);
    stakes.insert(ExternalNetworkId::Ethereum, 1u64);

    let info = GlobalSession { start_block_number: 0, sets, keys, stakes, total_stake: u64::MAX };

    let mut txn = test.db.txn();
    GlobalSessionsChannel::send(&mut txn, &(EvaluatorTest::GLOBAL_SESSION, info));
    txn.commit();

    EvaluatorTest::GLOBAL_SESSION
  };

  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      ExternalNetworkId::Bitcoin,
      &signed_cosign(global_session, ExternalNetworkId::Bitcoin, 5),
    );
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      ExternalNetworkId::Ethereum,
      &signed_cosign(global_session, ExternalNetworkId::Ethereum, 5),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::NonNotable },
    );
    txn.commit();
  }

  let mut task = test.into_task();
  TaskTest::assert_task_run_and_failed_with(&mut task, "weight_cosigned overflow").await;
}

#[tokio::test]
#[should_panic(expected = "fetching latest global session yet none declared")]
async fn evaluator_task_errors_when_no_global_session_in_channel() {
  let mut test = EvaluatorTest::default();

  {
    let mut txn = test.db.txn();
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 1, has_events: HasEvents::No });
    txn.commit();
  }

  let mut task = test.into_task();
  let _ = task.run_iteration().await;
}
