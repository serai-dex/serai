use std::{
  collections::HashMap,
  sync::atomic::Ordering,
  time::{Duration, Instant},
};

use rand_core::OsRng;
use serai_cosign_types::SignedCosign;
use serai_db::{Db as _, DbTxn, MemDb};
use serai_client_serai::abi::primitives::{
  crypto::Public,
  network_id::ExternalNetworkId,
  validator_sets::{ExternalValidatorSet, Session},
};

use serai_primitives::test_helpers::random_block_hash;
use serai_task::ContinuallyRan;

use crate::{
  Cosign, GlobalSession, HasEvents, NetworksLatestCosignedBlock,
  evaluator::{
    CosignEvaluatorTask, CosignedBlocks, CurrentlyEvaluatedGlobalSession, LatestEvaluatedBlock,
    REQUEST_COSIGNS_SPACING,
  },
  intend::{BlockEventData, BlockEvents, GlobalSessionsChannel},
  tests::{IntoTask, TaskTest, TestRequest, random_global_session},
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
  fn init_global_session(&mut self, start_block_number: u64) -> [u8; 32] {
    let global_session = random_global_session();
    let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };

    let mut keys = HashMap::new();
    keys.insert(ExternalNetworkId::Bitcoin, Public([1u8; 32]));

    let mut stakes = HashMap::new();
    stakes.insert(ExternalNetworkId::Bitcoin, 1u64);

    let info =
      GlobalSession { start_block_number, sets: vec![set], keys, stakes, total_stake: 1u64 };

    let mut txn = self.db.txn();
    GlobalSessionsChannel::send(&mut txn, &(global_session, info));
    txn.commit();

    global_session
  }
}

/// Verify evaluator post-run DB invariants.
///
/// After a successful task run, all input channels should be consumed and the
/// `CosignedBlocks` output channel should contain exactly the expected block range.
fn verify_db_invariants(db: &mut MemDb, expected_cosigned_range: Option<(u64, u64)>) {
  use serai_env::log::debug;

  let latest_evaluated = LatestEvaluatedBlock::get(db);
  let current_session = CurrentlyEvaluatedGlobalSession::get(db);
  let block_events_pending = BlockEvents::peek(db).is_some();
  let sessions_pending = GlobalSessionsChannel::peek(db).is_some();
  let cosigned_pending = CosignedBlocks::peek(db).is_some();

  debug!("LatestEvaluatedBlock: {latest_evaluated:?}");
  debug!(
    "CurrentlyEvaluatedGlobalSession: {:?}",
    current_session.as_ref().map(|(id, gs)| (hex::encode(id), gs.start_block_number))
  );
  debug!("BlockEvents pending: {block_events_pending}");
  debug!("GlobalSessionsChannel pending: {sessions_pending}");
  debug!("CosignedBlocks pending: {cosigned_pending}");

  // All input channels should be fully consumed
  assert!(!block_events_pending, "BlockEvents should be fully consumed");
  assert!(!sessions_pending, "GlobalSessionsChannel should be consumed");

  let has_session = current_session.is_some();

  let mut txn = db.txn();

  // Verify cosigned blocks output
  match expected_cosigned_range {
    Some((start, end)) => {
      assert!(has_session, "CurrentlyEvaluatedGlobalSession should exist after processing blocks");

      for expected_block in start ..= end {
        let (block_number, _time) = CosignedBlocks::try_recv(&mut txn)
          .unwrap_or_else(|| panic!("expected cosigned block {expected_block}"));
        debug!("CosignedBlock: block_number={block_number}");
        assert_eq!(block_number, expected_block, "cosigned block mismatch");
      }
      assert!(CosignedBlocks::try_recv(&mut txn).is_none(), "unexpected extra cosigned block");
    }
    None => {
      assert!(!has_session, "no session should exist when no blocks were processed");
      assert!(CosignedBlocks::try_recv(&mut txn).is_none(), "expected no cosigned blocks");
    }
  }
  txn.commit();
}

fn signed_cosign(
  global_session: [u8; 32],
  cosigner: ExternalNetworkId,
  block_number: u64,
) -> SignedCosign {
  SignedCosign {
    cosign: Cosign {
      global_session,
      block_number,
      block_hash: random_block_hash(&mut OsRng),
      cosigner,
    },
    signature: [0u8; 64],
  }
}

#[tokio::test]
async fn returns_false_with_no_block_events() {
  let mut test = EvaluatorTest::default();
  let mut task = test.into_task();
  TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
  verify_db_invariants(&mut test.db, None);
}

#[tokio::test]
async fn processes_blocks_with_no_events() {
  serai_env::init_logger();
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

  assert!(BlockEvents::peek(&test.db).is_none(), "BlockEvents should be fully consumed");
  assert!(
    CosignedBlocks::peek(&test.db).is_none(),
    "HasEvent::No blocks shouldn't produce CosignedBlocks"
  );
  assert_eq!(LatestEvaluatedBlock::get(&test.db), Some(2));
}

#[tokio::test]
async fn processes_notable_events_when_cosigned() {
  serai_env::init_logger();
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
  verify_db_invariants(&mut test.db, Some((1, 1)));
}

#[tokio::test]
async fn non_notable_uses_cached_known_cosign() {
  serai_env::init_logger();
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
  verify_db_invariants(&mut test.db, Some((1, 3)));
}

#[tokio::test]
async fn non_notable_with_cosign_returns_some() {
  serai_env::init_logger();
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
  verify_db_invariants(&mut test.db, Some((1, 1)));
}

#[tokio::test]
async fn non_notable_computes_lowest_common_block() {
  serai_env::init_logger();
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
    let id = random_global_session();
    GlobalSessionsChannel::send(&mut txn, &(id, info));
    txn.commit();

    id
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
  verify_db_invariants(&mut test.db, Some((1, 3)));
}

#[tokio::test]
async fn advances_global_session_at_start_block() {
  serai_env::init_logger();
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

  assert!(BlockEvents::peek(&test.db).is_none(), "BlockEvents should be fully consumed");
  assert!(
    CosignedBlocks::peek(&test.db).is_none(),
    "HasEvent::No blocks shouldn't produce CosignedBlocks"
  );
  assert_eq!(LatestEvaluatedBlock::get(&test.db), Some(3));

  let current =
    CurrentlyEvaluatedGlobalSession::get(&test.db).expect("should have current session");
  assert_eq!(current.0, session2, "should have transitioned to session 2");
  assert_eq!(current.1.start_block_number, 3, "session 2 should start at block 3");
}

mod errors {
  use super::*;

  #[tokio::test]
  async fn notable_events_without_cosign() {
    serai_env::init_logger();
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
    TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
    // On failure, global session was consumed but block events remain
    assert!(GlobalSessionsChannel::peek(&test.db).is_none());
    assert!(BlockEvents::peek(&test.db).is_some());

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

    TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
    assert!(GlobalSessionsChannel::peek(&test.db).is_none());
    assert!(BlockEvents::peek(&test.db).is_some());
  }

  #[tokio::test]
  async fn notable_events_without_stakes() {
    serai_env::init_logger();
    let mut test = EvaluatorTest::default();

    let global_session = {
      let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };

      let mut keys = HashMap::new();
      keys.insert(ExternalNetworkId::Bitcoin, Public([1u8; 32]));

      let stakes = HashMap::new();

      let info =
        GlobalSession { start_block_number: 0, sets: vec![set], keys, stakes, total_stake: 1u64 };

      let mut txn = test.db.txn();
      let id = random_global_session();
      GlobalSessionsChannel::send(&mut txn, &(id, info));
      txn.commit();

      id
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
    TaskTest::task_runs_and_fails_with(&mut task, "didn't have its stake").await;
  }

  #[tokio::test]
  async fn non_notable_events_without_cosign() {
    serai_env::init_logger();
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
    TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
    assert!(GlobalSessionsChannel::peek(&test.db).is_none());
    assert!(BlockEvents::peek(&test.db).is_some());

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

    TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
  }

  #[tokio::test]
  async fn non_notable_events_without_stakes() {
    serai_env::init_logger();
    let mut test = EvaluatorTest::default();

    let global_session = {
      let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };

      let mut keys = HashMap::new();
      keys.insert(ExternalNetworkId::Bitcoin, Public([1u8; 32]));

      let stakes = HashMap::new();

      let info =
        GlobalSession { start_block_number: 0, sets: vec![set], keys, stakes, total_stake: 1u64 };

      let mut txn = test.db.txn();
      let id = random_global_session();
      GlobalSessionsChannel::send(&mut txn, &(id, info));
      txn.commit();

      id
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
    TaskTest::task_runs_and_fails_with(&mut task, "didn't have its stake").await;
  }

  #[tokio::test]
  async fn non_notable_cosign_too_low_does_not_add_weight() {
    serai_env::init_logger();
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
    TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
  }

  #[tokio::test]
  async fn request_notable_cosigns_failure() {
    serai_env::init_logger();
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

    TaskTest::task_runs_and_fails_with(&mut task, "RequestError").await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "request_notable_cosigns should have been called");
  }

  #[tokio::test]
  async fn request_non_notable_cosigns_failure() {
    serai_env::init_logger();
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

    TaskTest::task_runs_and_fails_with(&mut task, "RequestError").await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "request_notable_cosigns should have been called");
  }

  #[tokio::test]
  #[should_panic(expected = "candidate's start block number ")]
  async fn panics_when_session_starts_after_block() {
    serai_env::init_logger();
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
      let id = random_global_session();
      CurrentlyEvaluatedGlobalSession::set(&mut txn, &(id, info));
      BlockEvents::send(&mut txn, &BlockEventData { block_number: 5, has_events: HasEvents::No });
      txn.commit();
    }

    let mut task = test.into_task();
    let _ = task.run_iteration().await;
  }

  #[tokio::test]
  #[should_panic(
    expected = "currently_evaluated_global_session_strict wasn't called incrementally"
  )]
  async fn panics_when_called_non_incrementally() {
    serai_env::init_logger();
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
  #[should_panic(expected = "attempt to add with overflow")]
  async fn weight_overflow_notable() {
    serai_env::init_logger();
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
      let id = random_global_session();
      GlobalSessionsChannel::send(&mut txn, &(id, info));
      txn.commit();

      id
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
    TaskTest::task_runs_and_fails_with(&mut task, "weight_cosigned overflow").await;
  }

  #[tokio::test]
  #[should_panic(expected = "attempt to add with overflow")]
  async fn weight_overflow_non_notable() {
    serai_env::init_logger();
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
      let id = random_global_session();
      GlobalSessionsChannel::send(&mut txn, &(id, info));
      txn.commit();

      id
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
    TaskTest::task_runs_and_fails_with(&mut task, "weight_cosigned overflow").await;
  }
}
