use std::{
  collections::HashMap,
  sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
  },
  time::{Duration, Instant},
};

use serai_db::{DbTxn, Db as _, MemDb};
use serai_client_serai::abi::primitives::{
  crypto::Public,
  validator_sets::{ExternalValidatorSet, Session},
};

use crate::{
  BlockHash, Cosign, ExternalNetworkId, GlobalSession, HasEvents, NetworksLatestCosignedBlock,
  SignedCosign,
  evaluator::{
    CosignEvaluatorTask, CosignedBlocks, CurrentlyEvaluatedGlobalSession, REQUEST_COSIGNS_SPACING,
  },
  intend::{BlockEventData, BlockEvents, GlobalSessionsChannel},
  tests::{IntoTask, Test},
};
use crate::RequestNotableCosigns;

use serai_task::{ContinuallyRan};

#[derive(Clone)]
pub(crate) struct TestRequest {
  pub(crate) calls: Arc<AtomicUsize>,
  pub(crate) should_error: bool,
}

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

#[derive(Debug)]
pub(crate) struct RequestError;

impl TestRequest {
  pub(crate) fn new(should_error: bool) -> (Self, Arc<AtomicUsize>) {
    let calls = Arc::new(AtomicUsize::new(0));
    (Self { calls: calls.clone(), should_error }, calls)
  }
}

impl RequestNotableCosigns for TestRequest {
  type Error = RequestError;

  fn request_notable_cosigns(
    &self,
    _global_session: [u8; 32],
  ) -> impl Send + core::future::Future<Output = Result<(), Self::Error>> {
    let calls = self.calls.clone();
    let should_error = self.should_error;
    async move {
      calls.fetch_add(1, Ordering::SeqCst);
      if should_error {
        Err(RequestError)
      } else {
        Ok(())
      }
    }
  }
}

impl EvaluatorTest {
  fn assert_no_currently_evaluated_global_session(&self) {
    assert_eq!(CurrentlyEvaluatedGlobalSession::get(&self.db).is_none(), true);
  }

  /// Asserts that cosigned blocks from start_block to end_block (inclusive) are present in order.
  fn assert_cosigned_blocks_range(&mut self, start_block: u64, end_block: u64) {
    let mut txn = self.db.txn();
    for expected_block in start_block..=end_block {
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

  fn assert_task_iteration_failed_at(&mut self, block_number: u64) {
    self.assert_no_global_sessions_channel();
    self.assert_has_block_events();
    self.assert_cosigned_blocks_range(block_number - 1, block_number - 1);
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
  Test::assert_task_run_and_check_progress(&mut task, false).await;
  test.assert_evaluator_db_is_clear();
}

#[tokio::test]
async fn evaluator_task_returns_false_with_genesis_block() {
  let mut test = EvaluatorTest::default();

  {
    let mut txn = test.db.txn();
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 0, has_events: HasEvents::No });
    txn.commit();
  }

  let mut task = test.into_task();
  Test::assert_task_run_and_check_progress(&mut task, false).await;
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
  Test::assert_task_run_and_check_progress(&mut task, true).await;
  test.assert_task_iteration_completed(1, 2);
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
  Test::assert_task_run_and_failed_with(&mut task, "wasn't yet cosigned").await;
  test.assert_task_iteration_failed_at(2);

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

  Test::assert_task_run_and_failed_with(&mut task, "wasn't yet cosigned").await;
  // test.assert_task_iteration_failed_at(2);
}
