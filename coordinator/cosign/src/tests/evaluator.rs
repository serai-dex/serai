use crate::{intend, evaluator::*, tests::*, *};

struct EvaluatorTest {
  db: MemDb,
}

impl_serai_task_test_struct!(EvaluatorTest, { db: db });

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
  /// Seed to the inted task's db channel the intend::GlobalCosigningSessionsChannel
  /// using a random and non-empty choice of external networks.
  fn seed_a_random_global_cosigning_session<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    start_block_number: u64,
  ) -> (GlobalCosigningSessionId, GlobalCosigningSession) {
    let sets = random_external_validator_sets(rng);
    let num_sets = sets.len();

    let mut keys = HashMap::with_capacity(num_sets);
    let mut stakes = HashMap::with_capacity(num_sets);
    let mut total_stake = 0u64;
    for &set in &sets {
      let network = set.network;
      keys.insert(network, random_public(rng));
      let stake = rng.gen_range(1u64 .. u64::MAX / 17);
      stakes.insert(network, stake);
      total_stake += stake;
    }

    let global_cosigning_session = GlobalCosigningSession::id(sets.clone());
    let global_cosigning_session_info = GlobalCosigningSession {
      start_block_number,
      cosigning_sets: sets,
      keys,
      stakes,
      total_stake,
    };

    let mut txn = self.db.txn();
    intend::GlobalCosigningSessionsChannel::send(
      &mut txn,
      &(global_cosigning_session, global_cosigning_session_info.clone()),
    );
    txn.commit();

    (global_cosigning_session, global_cosigning_session_info)
  }

  /// Like `seed_a_random_global_cosigning_session` but with empty stakes.
  /// for testing the "didn't have its stake" error.
  fn seed_a_random_stakeless_global_cosigning_session<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    start_block_number: u64,
  ) -> (GlobalCosigningSessionId, GlobalCosigningSession) {
    let sets = random_external_validator_sets(rng);
    let num_sets = sets.len();

    let mut keys = HashMap::with_capacity(num_sets);
    for &set in &sets {
      let network = set.network;
      keys.insert(network, random_public(rng));
    }

    let global_cosigning_session = GlobalCosigningSession::id(sets.clone());
    let global_cosigning_session_info = GlobalCosigningSession {
      start_block_number,
      cosigning_sets: sets,
      keys,
      stakes: HashMap::new(),
      total_stake: 0,
    };

    let mut txn = self.db.txn();
    intend::GlobalCosigningSessionsChannel::send(
      &mut txn,
      &(global_cosigning_session, global_cosigning_session_info.clone()),
    );
    txn.commit();

    (global_cosigning_session, global_cosigning_session_info)
  }
}

struct EvaluatorReplayState {
  sent_blocks: Vec<(u64, HasEvents)>,
}

impl EvaluatorReplayState {
  fn new() -> Self {
    Self { sent_blocks: vec![] }
  }

  fn seed_block_event(&mut self, txn: &mut impl DbTxn, block: (u64, HasEvents)) {
    intend::BlockEvents::send(
      txn,
      &intend::BlockEventData { block_number: block.0, has_events: block.1 },
    );
    self.sent_blocks.push(block);
  }

  fn seed_block_events(&mut self, txn: &mut impl DbTxn, blocks: &[(u64, HasEvents)]) {
    for &block in blocks {
      self.seed_block_event(txn, block);
    }
  }

  fn seed_block_range(
    &mut self,
    txn: &mut impl DbTxn,
    range: impl IntoIterator<Item = u64>,
    has_events: HasEvents,
  ) {
    for block_number in range {
      self.seed_block_event(txn, (block_number, has_events));
    }
  }

  /// Verify evaluator's post-run DB invariants against the blocks recorded.
  fn verify_db_invariants(&mut self, db: &mut MemDb) {
    use serai_env::log::debug;

    let block_events_pending = intend::BlockEvents::peek(db).is_some();
    debug!("intend::BlockEvents pending: {block_events_pending}");
    assert!(!block_events_pending, "intend::BlockEvents should be fully consumed");

    let expected_blocks: Vec<(u64, HasEvents)> = self.sent_blocks.drain(..).collect();

    if expected_blocks.is_empty() {
      let mut txn = db.txn();
      assert!(CosignedBlocks::try_recv(&mut txn).is_none(), "expected no cosigned blocks");
      txn.commit();
      return;
    }

    let mut txn = db.txn();
    for &(expected_block, has_events) in &expected_blocks {
      let expected_has_cosigns = !matches!(has_events, HasEvents::No);
      let (block_number, time, has_cosigns) = CosignedBlocks::try_recv(&mut txn)
        .unwrap_or_else(|| panic!("expected cosigned block {expected_block}"));

      debug!("CosignedBlock: block_number={block_number}, time={time}, has_cosigns={has_cosigns}");
      assert_eq!(block_number, expected_block, "cosigned block number mismatch");
      assert_eq!(
        has_cosigns, expected_has_cosigns,
        "cosigned block {expected_block} has_cosigns mismatch: \
         expected {expected_has_cosigns}, got {has_cosigns}",
      );
    }
    assert!(CosignedBlocks::try_recv(&mut txn).is_none(), "unexpected extra cosigned block");
    txn.commit();
  }
}

fn random_signed_cosign<R: RngCore + CryptoRng>(
  rng: &mut R,
  global_cosigning_session: GlobalCosigningSessionId,
  cosigner: ExternalNetworkId,
  block_number: u64,
) -> SignedCosign {
  SignedCosign {
    cosign: Cosign {
      global_cosigning_session,
      block_number,
      block_hash: random_block_hash(rng),
      cosigner,
    },
    signature: random_bytes(rng),
  }
}

#[test]
fn constants() {
  assert_eq!(COSIGN_COMMIT_THRESHOLD_NUMERATOR, 83);
  assert_eq!(COSIGN_COMMIT_THRESHOLD_DENOMINATOR, 100);
  const {
    assert!(COSIGN_COMMIT_THRESHOLD_NUMERATOR < COSIGN_COMMIT_THRESHOLD_DENOMINATOR);
  }
}

#[test]
fn cosign_threshold_formula() {
  let mut rng = new_test_rng();
  for _ in 0 .. 100 {
    let total_stake = rng.gen_range(1u64 .. u64::MAX / 17);
    let threshold = cosign_threshold(total_stake);
    let expected = u64::try_from((u128::from(total_stake) * 83) / 100).expect("threshold < 1") + 1;
    assert_eq!(threshold, expected, "mismatch for total_stake={total_stake}");
  }
}

mod errors {
  use super::*;

  #[tokio::test]
  async fn panics_on_evaluate_block_before_session_starts() {
    let mut rng = new_test_rng();
    let mut test = EvaluatorTest::default();
    let mut recorder = EvaluatorReplayState::new();

    // block needs to be at least 1 so that we subtract 1 later
    let block_to_evaluate = rng.next_u64().max(1);

    test.seed_a_random_global_cosigning_session(&mut rng, block_to_evaluate);

    // A current global cosigning session to evaluate exists, but we send a block event
    // for a block prior its start
    {
      let mut txn = test.db.txn();
      let drained_session = intend::GlobalCosigningSessionsChannel::try_recv(&mut txn).unwrap();
      CurrentGlobalCosigningSessionEvaluator::set(&mut txn, &drained_session);

      recorder.seed_block_event(&mut txn, (block_to_evaluate - 1, HasEvents::No));
      txn.commit();
    }

    let mut task = test.task();
    TaskTest::task_runs_and_panics_with(&mut task, "before session start").await;
  }

  #[tokio::test]
  async fn panics_on_non_increment_one_past_session_start() {
    let mut rng = new_test_rng();
    let mut test = EvaluatorTest::default();
    let mut recorder = EvaluatorReplayState::new();

    // we need to be able to add 2 for the jump
    let block_to_evaluate = rng.next_u64().min(u64::MAX - 2);

    test.seed_a_random_global_cosigning_session(&mut rng, block_to_evaluate);
    test.seed_a_random_global_cosigning_session(&mut rng, block_to_evaluate + 1);

    // A non-incremental jump that skips past a queued session's start, panics.
    {
      let mut txn = test.db.txn();
      recorder.seed_block_event(&mut txn, (block_to_evaluate + 2, HasEvents::No));
      txn.commit();
    }

    let mut task = test.task();
    TaskTest::task_runs_and_panics_with(&mut task, "wasn't called incrementally").await;
  }
}

mod progresses {
  use super::*;

  #[tokio::test]
  async fn processes_blocks_and_sessions_with_no_events() {
    let mut rng = new_test_rng();
    let mut test = EvaluatorTest::default();
    let mut recorder = EvaluatorReplayState::new();

    // Returns false (made no progress) on no blocks to evaluate
    {
      let mut task = test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
    }
    recorder.verify_db_invariants(&mut test.db);

    test.seed_a_random_global_cosigning_session(&mut rng, 0);

    // BlockEvents sent progresses, and CosignedBlocks are queued
    {
      {
        let mut txn = test.db.txn();
        recorder.seed_block_range(&mut txn, 0 ..= 4, HasEvents::No);
        txn.commit();
      }

      {
        let mut task = test.task();
        TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
      }
      recorder.verify_db_invariants(&mut test.db);
    }

    // Advances to the next global cosigning session when blocks reach its number
    {
      test.seed_a_random_global_cosigning_session(&mut rng, 0);
      test.seed_a_random_global_cosigning_session(&mut rng, 5);
      let (expected_session, _) = test.seed_a_random_global_cosigning_session(&mut rng, 10);

      // Process blocks 0..=14 (covers all three sessions)
      {
        let mut txn = test.db.txn();
        recorder.seed_block_range(&mut txn, 0 ..= 14, HasEvents::No);
        txn.commit();
      }

      {
        let mut task = test.task();
        TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
      }
      recorder.verify_db_invariants(&mut test.db);

      // Directly validate last session is latest
      let current =
        CurrentGlobalCosigningSessionEvaluator::get(&test.db).expect("should have current session");
      assert_eq!(current.0, expected_session, "should have transitioned to session 3");
      assert_eq!(current.1.start_block_number, 10, "session 3 should start at block 10");
    }
  }

  #[tokio::test]
  async fn processes_events_when_cosigned() {
    async fn processes_events_when_cosigned_helper(has_events: HasEvents) {
      let mut rng = new_test_rng();
      let mut test = EvaluatorTest::default();
      let mut recorder = EvaluatorReplayState::new();

      let (global_cosigning_session, global_cosigning_session_info) =
        test.seed_a_random_global_cosigning_session(&mut rng, 0);

      // Block with no crate::NetworksLatestCosignedBlockIntaken set fails
      {
        {
          let mut txn = test.db.txn();
          recorder.seed_block_events(&mut txn, &[(0, HasEvents::No), (1, has_events)]);
          txn.commit();
        }

        {
          let mut task = test.task();
          TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
        }
        assert!(
          intend::GlobalCosigningSessionsChannel::peek(&test.db).is_none(),
          "global cosigning session should be consumed"
        );
        assert!(
          intend::BlockEvents::peek(&test.db).is_some(),
          "block events should remain for retry"
        );

        // Still fails on retry even with enough time elapsed to re-request cosigns
        {
          let mut task = test.task();
          task.last_request_for_cosigns =
            Instant::now().checked_sub(Duration::from_secs(5)).unwrap();
          TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
        }
        assert!(
          intend::BlockEvents::peek(&test.db).is_some(),
          "block events should remain for retry"
        );
      }

      // Same block succeeds once cosign is intake
      {
        {
          let mut txn = test.db.txn();
          for set in &global_cosigning_session_info.cosigning_sets {
            crate::NetworksLatestCosignedBlockIntaken::set(
              &mut txn,
              global_cosigning_session,
              set.network,
              &random_signed_cosign(&mut rng, global_cosigning_session, set.network, 1),
            );
          }
          txn.commit();
        }

        {
          let mut task = test.task();
          TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
        }
        recorder.verify_db_invariants(&mut test.db);
      }

      // intake cosigns for a later block:
      // - Notable requires exact match, so still fails
      // - NonNotable uses >=, so succeeds
      {
        {
          let mut txn = test.db.txn();
          for set in &global_cosigning_session_info.cosigning_sets {
            crate::NetworksLatestCosignedBlockIntaken::set(
              &mut txn,
              global_cosigning_session,
              set.network,
              &random_signed_cosign(&mut rng, global_cosigning_session, set.network, 5),
            );
          }
          recorder.seed_block_event(&mut txn, (2, has_events));
          txn.commit();
        }

        {
          let mut task = test.task();
          match has_events {
            HasEvents::Notable => {
              TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
              assert!(
                intend::BlockEvents::peek(&test.db).is_some(),
                "block events should remain for retry"
              );
            }
            HasEvents::NonNotable => {
              TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
              recorder.verify_db_invariants(&mut test.db);
            }
            HasEvents::No => unreachable!(),
          }
        }
      }

      // Cosign for an earlier block doesn't satisfy either event type
      {
        let mut test = EvaluatorTest::default();
        let mut recorder = EvaluatorReplayState::new();

        let (global_cosigning_session, global_cosigning_session_info) =
          test.seed_a_random_global_cosigning_session(&mut rng, 0);

        {
          let mut txn = test.db.txn();
          for set in &global_cosigning_session_info.cosigning_sets {
            crate::NetworksLatestCosignedBlockIntaken::set(
              &mut txn,
              global_cosigning_session,
              set.network,
              &random_signed_cosign(&mut rng, global_cosigning_session, set.network, 2),
            );
          }
          recorder.seed_block_event(&mut txn, (5, has_events));
          txn.commit();
        }

        {
          let mut task = test.task();
          TaskTest::task_runs_and_fails_with(&mut task, "wasn't yet cosigned").await;
        }
      }

      // Multiple blocks succeed: Notable via exact-match loop, NonNotable via cache
      {
        let mut test = EvaluatorTest::default();
        let mut recorder = EvaluatorReplayState::new();

        let (global_cosigning_session, global_cosigning_session_info) =
          test.seed_a_random_global_cosigning_session(&mut rng, 0);

        let block_numbers: Vec<u64> =
          if matches!(has_events, HasEvents::NonNotable) { (0 .. 4).collect() } else { vec![99] };

        {
          let mut txn = test.db.txn();
          for i_block_number in &block_numbers {
            for set in &global_cosigning_session_info.cosigning_sets {
              crate::NetworksLatestCosignedBlockIntaken::set(
                &mut txn,
                global_cosigning_session,
                set.network,
                &random_signed_cosign(
                  &mut rng,
                  global_cosigning_session,
                  set.network,
                  *i_block_number,
                ),
              );
            }
            recorder.seed_block_event(&mut txn, (*i_block_number, has_events));
          }
          txn.commit();
        }

        {
          let mut task = test.task();
          TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
        }
        recorder.verify_db_invariants(&mut test.db);
      }

      // Cosigned block without stakes panics
      {
        let mut test = EvaluatorTest::default();
        let mut recorder = EvaluatorReplayState::new();

        let (global_cosigning_session, global_cosigning_session_info) =
          test.seed_a_random_stakeless_global_cosigning_session(&mut rng, 0);

        // Notable needs exact cosign at block 1; NonNotable accepts any >= 1
        let cosign_block = match has_events {
          HasEvents::Notable => 1,
          HasEvents::NonNotable => 5,
          HasEvents::No => unreachable!(),
        };

        {
          let mut txn = test.db.txn();
          for set in &global_cosigning_session_info.cosigning_sets {
            crate::NetworksLatestCosignedBlockIntaken::set(
              &mut txn,
              global_cosigning_session,
              set.network,
              &random_signed_cosign(&mut rng, global_cosigning_session, set.network, cosign_block),
            );
          }
          recorder.seed_block_event(&mut txn, (1, has_events));
          txn.commit();
        }

        {
          let mut task = test.task();
          TaskTest::task_runs_and_panics_with(&mut task, "didn't have its stake").await;
        }
      }

      // request_notable_cosigns failure propagates
      {
        let mut test = EvaluatorTest::default();
        let mut recorder = EvaluatorReplayState::new();

        test.seed_a_random_global_cosigning_session(&mut rng, 0);

        {
          let mut txn = test.db.txn();
          recorder.seed_block_event(&mut txn, (1, has_events));
          txn.commit();
        }

        let (request, calls) = TestRequest::new(true);
        {
          let mut task = CosignEvaluatorTask {
            db: test.db.clone(),
            request,
            last_request_for_cosigns: Instant::now()
              .checked_sub(REQUEST_COSIGNS_SPACING)
              .unwrap()
              .checked_sub(Duration::from_secs(5))
              .unwrap(),
          };

          TaskTest::task_runs_and_fails_with(&mut task, "RequestError").await;
        }
        assert_eq!(
          calls.load(Ordering::SeqCst),
          1,
          "request_notable_cosigns should have been called"
        );
      }
    }

    processes_events_when_cosigned_helper(HasEvents::Notable).await;
    processes_events_when_cosigned_helper(HasEvents::NonNotable).await;
  }

  #[tokio::test]
  async fn fuzzed_event_processing() {
    let mut rng = new_test_rng();
    let mut test = EvaluatorTest::default();
    let mut recorder = EvaluatorReplayState::new();
    let num_blocks = 100u64;

    // Generate a random number of global cosigning sessions (1..=4) at random starts.
    // Each session has at most one Notable block (the last block before the
    // next session's start), matching real-world behavior where a Notable
    // event triggers a new cosigning session.
    let num_sessions = rng.gen_range(1usize ..= 4);
    let mut session_starts = vec![0u64];
    while session_starts.len() < num_sessions {
      let next = session_starts.last().unwrap() + rng.gen_range(20u64 ..= 60u64);
      if next <= num_blocks {
        session_starts.push(next);
      } else {
        break;
      }
    }

    let stored_sessions: Vec<(GlobalCosigningSessionId, GlobalCosigningSession)> = session_starts
      .iter()
      .map(|&start| test.seed_a_random_global_cosigning_session(&mut rng, start))
      .collect();

    let notable_blocks: Vec<u64> = (0 .. session_starts.len())
      .map(|i| if i + 1 < session_starts.len() { session_starts[i + 1] - 1 } else { num_blocks })
      .collect();

    let mut txn = test.db.txn();

    // Pre-seed cosigns and BlockEvents for each session.
    {
      for i in 0 .. session_starts.len() {
        let (global_cosigning_session_id, global_cosigning_session_info) = &stored_sessions[i];
        let notable_block = notable_blocks[i];
        let start = session_starts[i];

        for set in &global_cosigning_session_info.cosigning_sets {
          crate::NetworksLatestCosignedBlockIntaken::set(
            &mut txn,
            *global_cosigning_session_id,
            set.network,
            &random_signed_cosign(
              &mut rng,
              *global_cosigning_session_id,
              set.network,
              notable_block,
            ),
          );
        }

        // Generate blocks in [start, notable_block]:
        //   - The Notable block itself
        //   - All other blocks: random No or NonNotable
        for block in start ..= notable_block {
          let has_events = if block == notable_block {
            HasEvents::Notable
          } else if rng.gen::<bool>() {
            HasEvents::No
          } else {
            HasEvents::NonNotable
          };
          recorder.seed_block_event(&mut txn, (block, has_events));
        }
      }

      txn.commit();
    }

    {
      let mut task = test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    recorder.verify_db_invariants(&mut test.db);
  }
}
