#![expect(clippy::unchecked_time_subtraction)]

use crate::{intend::*, evaluator::*, tests::*, *};

struct EvaluatorTest {
  db: MemDb,
}

impl Default for EvaluatorTest {
  fn default() -> Self {
    Self { db: MemDb::new() }
  }
}

impl IntoTask for EvaluatorTest {
  type Task = CosignEvaluatorTask<MemDb, TestRequest>;

  fn task(&self) -> Self::Task {
    let (request, _calls) = TestRequest::new(false);
    CosignEvaluatorTask { db: self.db.clone(), request, last_request_for_cosigns: Instant::now() }
  }
}

impl EvaluatorTest {
  fn init_global_session(&mut self, start_block_number: u64) -> ([u8; 32], ExternalNetworkId) {
    let global_session = random_global_session(&mut OsRng);
    let set = random_validator_set(&mut OsRng);
    let info = build_global_session(
      set,
      random_public(&mut OsRng),
      OsRng.gen_range(1 ..= u64::MAX),
      start_block_number,
    );

    let mut txn = self.db.txn();
    GlobalSessionsChannel::send(&mut txn, &(global_session, info));
    txn.commit();

    (global_session, set.network)
  }

  /// Like `init_global_session` but with empty stakes, for testing the "didn't have its stake"
  /// error.
  fn init_stakeless_global_session(
    &mut self,
    start_block_number: u64,
  ) -> ([u8; 32], ExternalNetworkId) {
    let global_session = random_global_session(&mut OsRng);
    let network = random_external_network_id(&mut OsRng);
    let set = ExternalValidatorSet { network, session: Session(OsRng.gen()) };

    let mut keys = HashMap::new();
    keys.insert(network, random_public(&mut OsRng));

    let info = GlobalSession {
      start_block_number,
      sets: vec![set],
      keys,
      stakes: HashMap::new(),
      // total_stake is not important,
      // the 0 stake test fails before it is used
      total_stake: OsRng.next_u64(),
    };

    let mut txn = self.db.txn();
    GlobalSessionsChannel::send(&mut txn, &(global_session, info));
    txn.commit();

    (global_session, network)
  }
}

/// Verify evaluator's post-run DB invariants.
///
/// After a successful task run, all input channels should be consumed and the
/// `CosignedBlocks` output channel should contain exactly the expected block range.
fn verify_db_invariants(db: &mut MemDb, expected_cosigned_range: Option<(u64, u64)>) {
  use serai_env::log::debug;

  let current_session = CurrentlyEvaluatedGlobalSession::get(db);
  let block_events_pending = BlockEvents::peek(db).is_some();
  let sessions_pending = GlobalSessionsChannel::peek(db).is_some();
  let cosigned_pending = CosignedBlocks::peek(db).is_some();

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
        let (block_number, _time, _has_events) = CosignedBlocks::try_recv(&mut txn)
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
    signature: random_bytes_64(&mut OsRng),
  }
}

#[tokio::test]
async fn processes_blocks_with_no_events() {
  let mut test = EvaluatorTest::default();

  // Returns false (made no progress) on no blocks to evaluate
  {
    let mut task = test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
    verify_db_invariants(&mut test.db, None);
  }

  test.init_global_session(0);

  // Sent BlockEvents progress and with no events are sent to CosignedBlocks
  {
    let mut txn = test.db.txn();
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 0, has_events: HasEvents::No });
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 1, has_events: HasEvents::No });
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 2, has_events: HasEvents::No });
    txn.commit();

    let mut task = test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&mut test.db, Some((0, 2)));
  }

  // Advances to the next global session when blocks reach its start_block_number
  {
    let (session2, _) = test.init_global_session(6);

    {
      let mut txn = test.db.txn();
      for block_number in 3 ..= 6 {
        BlockEvents::send(&mut txn, &BlockEventData { block_number, has_events: HasEvents::No });
      }
      txn.commit();
    }

    let mut task = test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&mut test.db, Some((3, 6)));

    let current =
      CurrentlyEvaluatedGlobalSession::get(&test.db).expect("should have current session");
    assert_eq!(current.0, session2, "should have transitioned to session 2");
    assert_eq!(current.1.start_block_number, 6, "session 2 should start at block 6");
  }
}

#[tokio::test]
async fn processes_notable_events_when_cosigned() {
  let mut test = EvaluatorTest::default();
  let (global_session, network) = test.init_global_session(0);

  // Notable block with no NetworksLatestCosignedBlock set fails
  {
    let mut txn = test.db.txn();
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 0, has_events: HasEvents::No });
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::Notable },
    );
    txn.commit();

    let mut task = test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
    assert!(GlobalSessionsChannel::peek(&test.db).is_none(), "global session should be consumed");
    assert!(BlockEvents::peek(&test.db).is_some(), "block events should remain for retry");

    // Still fails on retry even with enough time elapsed to re-request cosigns
    let mut task = test.task();
    task.last_request_for_cosigns = Instant::now() - Duration::from_secs(5);
    TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
    assert!(BlockEvents::peek(&test.db).is_some(), "block events should remain for retry");
  }

  // Same block succeeds once cosign is intake
  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      network,
      &signed_cosign(global_session, network, 1),
    );
    txn.commit();

    let mut task = test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&mut test.db, Some((0, 1)));
  }

  // Cosign for a later block doesn't satisfy Notable (requires exact block_number match)
  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      network,
      &signed_cosign(global_session, network, 5),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 2, has_events: HasEvents::Notable },
    );
    txn.commit();

    let mut task = test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
    assert!(BlockEvents::peek(&test.db).is_some(), "block events should remain for retry");
  }

  // Cosign for an earlier block doesn't satisfy Notable either
  // (BlockEvents already had sent block 2 from the branch above
  // but the cosign is for block 1)
  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      network,
      &signed_cosign(global_session, network, 1),
    );
    txn.commit();

    let mut task = test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
    assert!(BlockEvents::peek(&test.db).is_some(), "block events should remain for retry");
  }

  // Each Notable block succeeds when cosigned with its exact block number
  {
    for block_number in 2 .. 4 {
      let mut txn = test.db.txn();
      NetworksLatestCosignedBlock::set(
        &mut txn,
        global_session,
        network,
        &signed_cosign(global_session, network, block_number),
      );
      // (block 2 is already in BlockEvents)
      if block_number > 2 {
        BlockEvents::send(
          &mut txn,
          &BlockEventData { block_number, has_events: HasEvents::Notable },
        );
      }
      txn.commit();

      let mut task = test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
      verify_db_invariants(&mut test.db, Some((block_number, block_number)));
    }
  }

  // Cosigned Notable block without stakes fails
  {
    let mut test = EvaluatorTest::default();
    let (global_session, network) = test.init_stakeless_global_session(0);

    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      network,
      &signed_cosign(global_session, network, 1),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::Notable },
    );
    txn.commit();

    let mut task = test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "didn't have its stake").await;
  }

  // request_notable_cosigns failure propagates
  {
    let mut test = EvaluatorTest::default();
    test.init_global_session(0);

    let mut txn = test.db.txn();
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::Notable },
    );
    txn.commit();

    let (request, calls) = TestRequest::new(true);
    let mut task = CosignEvaluatorTask {
      db: test.db.clone(),
      request,
      last_request_for_cosigns: Instant::now() - REQUEST_COSIGNS_SPACING - Duration::from_secs(5),
    };

    TaskTest::task_runs_and_fails_with(&mut task, "RequestError").await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "request_notable_cosigns should have been called");
  }
}

#[tokio::test]
async fn processes_non_notable_events_when_cosigned() {
  let mut test = EvaluatorTest::default();
  let (global_session, network) = test.init_global_session(0);

  // NonNotable block with no NetworksLatestCosignedBlock set fails
  {
    let mut txn = test.db.txn();
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 0, has_events: HasEvents::No });
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::NonNotable },
    );
    txn.commit();

    let mut task = test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
    assert!(GlobalSessionsChannel::peek(&test.db).is_none(), "global session should be consumed");
    assert!(BlockEvents::peek(&test.db).is_some(), "block events should remain for retry");

    // Still fails on retry even with enough time elapsed to re-request cosigns
    let mut task = test.task();
    task.last_request_for_cosigns = Instant::now() - Duration::from_secs(5);
    TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
    assert!(BlockEvents::peek(&test.db).is_some(), "block events should remain for retry");
  }

  // Same block succeeds once cosign is present
  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      network,
      &signed_cosign(global_session, network, 1),
    );
    txn.commit();

    let mut task = test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&mut test.db, Some((0, 1)));
  }

  // Unlike Notable, a cosign for a later block satisfies NonNotable (uses >=)
  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      network,
      &signed_cosign(global_session, network, 5),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 2, has_events: HasEvents::NonNotable },
    );
    txn.commit();

    let mut task = test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&mut test.db, Some((2, 2)));
  }

  // Cosign for an earlier block doesn't satisfy NonNotable (uses >=)
  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      network,
      &signed_cosign(global_session, network, 1),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 3, has_events: HasEvents::NonNotable },
    );
    txn.commit();

    let mut task = test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
    assert!(BlockEvents::peek(&test.db).is_some(), "block events should remain for retry");
  }

  // Multiple NonNotable blocks in one run via cached known_cosign
  // (block 3 is already in BlockEvents from the failed branch above)
  {
    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      network,
      &signed_cosign(global_session, network, 10),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 4, has_events: HasEvents::NonNotable },
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 5, has_events: HasEvents::NonNotable },
    );
    txn.commit();

    let mut task = test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&mut test.db, Some((3, 5)));
  }

  // Cosigned NonNotable block without stakes fails
  {
    let mut test = EvaluatorTest::default();
    let (global_session, network) = test.init_stakeless_global_session(0);

    let mut txn = test.db.txn();
    NetworksLatestCosignedBlock::set(
      &mut txn,
      global_session,
      network,
      &signed_cosign(global_session, network, 5),
    );
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::NonNotable },
    );
    txn.commit();

    let mut task = test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "didn't have its stake").await;
  }

  // request_notable_cosigns failure propagates
  {
    let mut test = EvaluatorTest::default();
    test.init_global_session(0);

    let mut txn = test.db.txn();
    BlockEvents::send(
      &mut txn,
      &BlockEventData { block_number: 1, has_events: HasEvents::NonNotable },
    );
    txn.commit();

    let (request, calls) = TestRequest::new(true);
    let mut task = CosignEvaluatorTask {
      db: test.db.clone(),
      request,
      last_request_for_cosigns: Instant::now() - REQUEST_COSIGNS_SPACING - Duration::from_secs(5),
    };

    TaskTest::task_runs_and_fails_with(&mut task, "RequestError").await;
    assert_eq!(calls.load(Ordering::SeqCst), 1, "request_notable_cosigns should have been called");
  }
}

mod errors {
  use super::*;

  #[tokio::test]
  #[should_panic(expected = "candidate's start block number ")]
  async fn panics_when_session_starts_after_block() {
    let mut test = EvaluatorTest::default();
    let start_block_number: u64 = OsRng.gen_range(2 ..= 100);
    test.init_global_session(start_block_number);

    // Move the session from the channel into CurrentlyEvaluatedGlobalSession
    let mut txn = test.db.txn();
    let session = GlobalSessionsChannel::try_recv(&mut txn).unwrap();
    CurrentlyEvaluatedGlobalSession::set(&mut txn, &session);
    BlockEvents::send(
      &mut txn,
      &BlockEventData {
        block_number: OsRng.gen_range(0 .. start_block_number),
        has_events: HasEvents::No,
      },
    );
    txn.commit();

    let mut task = test.task();
    // will panic
    let _ = task.run_iteration().await;
  }

  #[tokio::test]
  #[should_panic(
    expected = "currently_evaluated_global_session_strict wasn't called incrementally"
  )]
  async fn panics_when_called_non_incrementally() {
    let mut test = EvaluatorTest::default();
    test.init_global_session(0);
    test.init_global_session(5);

    {
      let mut txn = test.db.txn();
      BlockEvents::send(&mut txn, &BlockEventData { block_number: 10, has_events: HasEvents::No });
      txn.commit();
    }

    let mut task = test.task();
    // will panic
    let _ = task.run_iteration().await;
  }

  fn setup_weight_overflow(has_events: HasEvents) -> CosignEvaluatorTask<MemDb, TestRequest> {
    let mut test = EvaluatorTest::default();
    let cosign_block = match has_events {
      HasEvents::Notable => 1u64,
      HasEvents::NonNotable => 5u64,
      HasEvents::No => unreachable!(),
    };

    let overflowing_stake_global_session = {
      let sets = vec![
        ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) },
        ExternalValidatorSet { network: ExternalNetworkId::Ethereum, session: Session(0) },
      ];

      let mut keys = HashMap::new();
      keys.insert(ExternalNetworkId::Bitcoin, random_public(&mut OsRng));
      keys.insert(ExternalNetworkId::Ethereum, random_public(&mut OsRng));

      let mut stakes = HashMap::new();
      stakes.insert(ExternalNetworkId::Bitcoin, u64::MAX);
      stakes.insert(ExternalNetworkId::Ethereum, OsRng.next_u64());

      let info = GlobalSession {
        start_block_number: 0,
        sets,
        keys,
        stakes,
        // total_stake is not important,
        // the overflow will panic before it is used
        total_stake: u64::MAX,
      };

      let mut txn = test.db.txn();
      let id = random_global_session(&mut OsRng);
      GlobalSessionsChannel::send(&mut txn, &(id, info));
      txn.commit();

      id
    };

    let mut txn = test.db.txn();
    for network in [ExternalNetworkId::Bitcoin, ExternalNetworkId::Ethereum] {
      NetworksLatestCosignedBlock::set(
        &mut txn,
        overflowing_stake_global_session,
        network,
        &signed_cosign(overflowing_stake_global_session, network, cosign_block),
      );
    }
    BlockEvents::send(&mut txn, &BlockEventData { block_number: 1, has_events });
    txn.commit();

    test.task()
  }

  #[tokio::test]
  #[should_panic(expected = "attempt to add with overflow")]
  async fn panics_on_weight_overflow_notable() {
    let mut task = setup_weight_overflow(HasEvents::Notable);
    TaskTest::task_runs_and_fails_with(&mut task, "weight_cosigned overflow").await;
  }

  #[tokio::test]
  #[should_panic(expected = "attempt to add with overflow")]
  async fn panics_on_weight_overflow_non_notable() {
    let mut task = setup_weight_overflow(HasEvents::NonNotable);
    TaskTest::task_runs_and_fails_with(&mut task, "weight_cosigned overflow").await;
  }
}
