use serai_shim_rpc::test_helpers::*;

use crate::{intend::*, tests::*, *};

struct IntendTestStruct {
  serai: Arc<Serai>,
  db: MemDb,
}

impl IntoTask for IntendTestStruct {
  type Task = CosignIntendTask<MemDb>;

  fn task(&self) -> Self::Task {
    CosignIntendTask { db: self.db.clone(), serai: self.serai.clone() }
  }
}

/// Create a [`SeraiShimRpc`] and a [`IntendTestStruct`] connected to its Serai RPC.
async fn setup_mock_test() -> (SeraiShimRpc, IntendTestStruct) {
  let (shim, serai) = setup_shim_serai().await;
  (shim, IntendTestStruct { serai, db: MemDb::new() })
}

/// Verify all of intend's post-run DB invariants by replaying events from the Serai node.
async fn verify_db_invariants(db: &MemDb, serai: &Serai, num_blocks: usize) {
  let num_blocks_u64 = u64::try_from(num_blocks).unwrap();

  // ScanCosignFrom should point to the block after the last processed
  let scan_from = ScanCosignFrom::get(db);
  serai_env::debug!("ScanCosignFrom: {scan_from:?}");
  assert_eq!(
    scan_from,
    Some(num_blocks_u64),
    "ScanCosignFrom should be {num_blocks} after processing blocks 0..={}",
    num_blocks - 1
  );

  // Replay events from the shim node to compute expected DB state.
  let mut expected_stakes = HashMap::<(ExternalNetworkId, SeraiAddress), u64>::new();
  let mut expected_latest_set = HashMap::<ExternalNetworkId, (Session, u64)>::new();
  let mut decided_validators = HashMap::<ExternalValidatorSet, Vec<SeraiAddress>>::new();
  let mut next_session = HashMap::<ExternalNetworkId, u32>::new();
  let mut set_keys_count = 0usize;

  for block_num in 0 .. num_blocks_u64 {
    let block = serai.block_by_number(block_num).await.unwrap().unwrap();
    let hash = block.header.hash();
    let events = serai.events(hash).await.unwrap();
    let vset = events.validator_sets();

    for event in vset.allocation_events() {
      let Event::Allocation { validator, network, amount } = event else { continue };
      let Ok(net) = ExternalNetworkId::try_from(*network) else { continue };
      *expected_stakes.entry((net, *validator)).or_insert(0) += amount.0;
    }
    for event in vset.deallocation_events() {
      let Event::Deallocation { validator, network, amount, .. } = event else { continue };
      let Ok(net) = ExternalNetworkId::try_from(*network) else { continue };
      *expected_stakes.entry((net, *validator)).or_insert(0) -= amount.0;
    }
    for event in vset.set_decided_events() {
      let Event::SetDecided { set, validators } = event else { continue };
      let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };
      decided_validators.insert(set, validators.iter().map(|(v, _)| *v).collect());
    }
    for event in vset.set_keys_events() {
      let Event::SetKeys { set, .. } = event else { continue };
      let validators = decided_validators.get(set).cloned().unwrap();
      let mut total_stake = 0u64;
      for v in &validators {
        total_stake += expected_stakes.get(&(set.network, *v)).copied().unwrap_or(0);
      }
      if total_stake > 0 {
        set_keys_count += 1;
        expected_latest_set.insert(set.network, (set.session, total_stake));
      }
      *next_session.entry(set.network).or_insert(0) += 1;
    }
  }

  // Verify Stakes match the expected.
  for (&(network, validator), &expected_amount) in &expected_stakes {
    let db_stake = Stakes::get(db, network, validator);
    serai_env::debug!(
      "Stakes[{network:?}, {validator:?}]: db={db_stake:?}, expected={expected_amount}"
    );
    assert_eq!(
      db_stake,
      Some(Amount(expected_amount)),
      "stake mismatch for ({network:?}, {validator:?}): db={db_stake:?}, expected={expected_amount}"
    );
  }

  // Verify LatestSet matches the expected.
  for (&network, &(session, stake)) in &expected_latest_set {
    let latest = LatestSet::get(db, network);
    serai_env::debug!(
      "LatestSet[{network:?}]: db={latest:?}, expected=(session={session:?}, stake={stake})"
    );
    assert!(latest.is_some(), "LatestSet should exist for {network:?}");
    let latest = latest.unwrap();
    assert_eq!(latest.session, session, "LatestSet session mismatch for {network:?}");
    assert_eq!(latest.stake.0, stake, "LatestSet stake mismatch for {network:?}");
  }

  // No pending Validators entries (all should have been taken by SetKeys).
  for &network in expected_latest_set.keys() {
    let session_num = next_session.get(&network).copied().unwrap_or(0);
    if session_num > 0 {
      let last_set = ExternalValidatorSet { network, session: Session(session_num - 1) };
      let validators = Validators::get(db, last_set);
      serai_env::debug!("Validators[{last_set:?}]: {validators:?} (should be None)");
      assert_eq!(
        validators, None,
        "Validators for {last_set:?} should have been consumed by SetKeys"
      );
    }
  }

  // Log and verify LatestGlobalSessionIntended
  let latest_session_id = LatestGlobalSessionIntended::get(db);
  serai_env::debug!("LatestGlobalSessionIntended: {:?}", latest_session_id.map(hex::encode));

  // If any SetKeys happened, a GlobalSession should exist with consistent total_stake
  if set_keys_count > 0 {
    assert!(
      latest_session_id.is_some(),
      "LatestGlobalSessionIntended should exist after {set_keys_count} SetKeys events",
    );
    let session_id = latest_session_id.unwrap();
    let session = GlobalSessions::get(db, session_id);
    assert!(session.is_some(), "GlobalSession should exist");
    let session = session.unwrap();

    serai_env::debug!(
      "GlobalSession {}: start_block_number={}, total_stake={}, sets={:?}, stakes={:?}",
      &hex::encode(&session_id[.. 8]),
      session.start_block_number,
      session.total_stake,
      session.sets,
      session.stakes,
    );
    serai_env::debug!("last_block: {:?}", GlobalSessionsLastBlock::get(db, session_id));

    let sum: u64 = session.stakes.values().sum();
    assert_eq!(
      session.total_stake, sum,
      "GlobalSession total_stake should equal sum of individual stakes"
    );
  }

  // SubstrateBlockHash index
  let max_block = scan_from.unwrap_or(0);
  if max_block > 0 {
    serai_env::debug!("SubstrateBlockHash index ({max_block} blocks):");
    for b in 0 .. max_block {
      if let Some(hash) = SubstrateBlockHash::get(db, b) {
        serai_env::debug!("  #{b}: {}…", &hex::encode(&hash.0[.. 8]));
      }
    }
  }

  serai_env::info!(
    "DB invariants verified: {} blocks, {} stake entries, {} LatestSets, {} SetKeys events",
    num_blocks,
    expected_stakes.len(),
    expected_latest_set.len(),
    set_keys_count
  );

  /*
    TODO:

    BuildsUpon: () -> IncrementalUnbalancedMerkleTree,
    GlobalSessionsChannel: () -> ([u8; 32], GlobalSession),
    BlockEvents: () -> BlockEventData,
    IntendedCosigns: (set: ExternalValidatorSet) -> CosignIntent,
  */
}

mod errors {
  use super::*;

  #[tokio::test]
  #[should_panic(expected = "node's block #2 doesn't build upon the block #1 prior indexed")]
  async fn panics_if_chain_is_not_linear() {
    let (shim, task_test) = setup_mock_test().await;

    shim.make_block(0, vec![]).await;
    shim.make_block(1, vec![]).await;
    shim.make_non_linear_block(2, vec![]).await;

    let mut task = task_test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "doesn't build upon").await;
  }

  #[tokio::test]
  #[should_panic(expected = "couldn't get block #0 which should've been finalized")]
  async fn panics_if_block_not_found() {
    let (_shim, task_test) = setup_mock_test().await;

    // No blocks yet, fails because serai.latest_finalized_block_number() defaults to 0
    // even without block 0 existing yet, so it fails when getting block 0
    let mut task = task_test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "").await;
  }

  #[tokio::test]
  #[should_panic(expected = "couldn't get block #2 which should've been finalized")]
  async fn panics_if_later_block_not_found() {
    let (shim, task_test) = setup_mock_test().await;

    shim.make_block(0, vec![]).await;
    shim.make_block(1, vec![]).await;
    shim.make_block(2, vec![]).await;
    shim.set_block_missing(2).await;

    let mut task = task_test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "").await;
  }

  #[tokio::test]
  async fn handles_rpc_error_on_block_fetch() {
    let (shim, task_test) = setup_mock_test().await;

    shim.make_block(0, vec![]).await;
    shim.make_block(1, vec![]).await;
    shim.make_block(2, vec![]).await;
    shim.set_block_number_error("blockchain/block", 2, "connection refused").await;

    let mut task = task_test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching block").await;

    assert_eq!(ScanCosignFrom::get(&task_test.db), Some(2));

    shim.clear_block_number_error("blockchain/block", 2).await;

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&task_test.db, &task_test.serai, 3).await;
  }

  #[tokio::test]
  async fn handles_rpc_error_on_events_fetch() {
    let (shim, task_test) = setup_mock_test().await;

    shim.make_block(0, vec![]).await;
    shim.make_block(1, vec![]).await;
    let block2_hash = shim.make_block(2, vec![]).await;
    shim.set_block_hash_error("blockchain/events", block2_hash, "timeout").await;

    let mut task = task_test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching events").await;

    assert_eq!(ScanCosignFrom::get(&task_test.db), Some(2));

    shim.clear_block_hash_error("blockchain/events", block2_hash).await;

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&task_test.db, &task_test.serai, 3).await;
  }

  #[tokio::test]
  #[should_panic(expected = "validator set from Event::SetDecided was empty")]
  async fn errors_if_set_decided_has_empty_validators() {
    let (shim, task_test) = setup_mock_test().await;
    shim.make_block(0, vec![]).await;

    let empty_set_decided = set_decided_event(
      ValidatorSet {
        network: NetworkId::External(ExternalNetworkId::Bitcoin),
        session: Session(0),
      },
      vec![],
    );
    shim.make_block(1, vec![vec![empty_set_decided]]).await;

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
  }

  #[tokio::test]
  async fn handles_rpc_error_on_latest_finalized() {
    let (shim, task_test) = setup_mock_test().await;

    shim.make_block(0, vec![]).await;
    shim.make_block(1, vec![]).await;
    shim.set_error("blockchain/latest_finalized_block_number", "network error").await;

    let mut task = task_test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching latest finalized").await;

    // No blocks processed, error happened before scanning
    assert_eq!(ScanCosignFrom::get(&task_test.db), None);

    shim.clear_error("blockchain/latest_finalized_block_number").await;

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&task_test.db, &task_test.serai, 2).await;
  }
}

#[tokio::test]
async fn deallocating_zero_is_a_noop() {
  let (shim, task_test) = setup_mock_test().await;

  let network = NetworkId::External(ExternalNetworkId::Bitcoin);

  {
    let validator = random_serai_address(&mut OsRng);

    // Block 0: allocate 0 stake to the validator
    shim.make_block(0, vec![vec![allocation_event(validator, network, 0)]]).await;
    // Block 1: deallocate 0 from the same validator
    shim.make_block(1, vec![vec![deallocation_event(validator, network, 0)]]).await;

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    // Verify it works and the stake is unchanged after the 0-deallocation
    let stake = Stakes::get(&task_test.db, ExternalNetworkId::Bitcoin, validator);
    assert_eq!(stake, Some(Amount(0)), "stake should be unchanged after deallocating 0");
  }

  {
    let validator = random_serai_address(&mut OsRng);
    let amount = OsRng.next_u64();
    // Block 2: allocate stake to the validator
    shim.make_block(2, vec![vec![allocation_event(validator, network, amount)]]).await;
    // Block 3: deallocate 0 from the same validator
    shim.make_block(3, vec![vec![deallocation_event(validator, network, 0)]]).await;

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    // Verify the 0-deallocation works and the stake is unchanged after it
    let stake = Stakes::get(&task_test.db, ExternalNetworkId::Bitcoin, validator);
    assert_eq!(stake, Some(Amount(amount)), "stake should be unchanged after deallocating 0");
  }

  {
    let validator = random_serai_address(&mut OsRng);
    // deallocate 0 from a non-existent validator
    shim.make_block(4, vec![vec![deallocation_event(validator, network, 0)]]).await;

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    let stake = Stakes::get(&task_test.db, ExternalNetworkId::Bitcoin, validator);
    // TODO: For a Stake which is `Amount(0)`, should we optimize the state by setting to `None`?
    assert_eq!(stake, Some(Amount(0)));
  }
}

#[tokio::test]
async fn fuzzed_event_processing() {
  *INIT_LOGGER;

  let num_blocks = 1000;

  let mut fuzzer = EventFuzzer::new();
  let blocks = fuzzer.generate_blocks(num_blocks);

  serai_env::info!("Fuzz test: {} blocks, {} validators", num_blocks, fuzzer.validators.len());

  let (shim, task_test) = setup_mock_test().await;
  for (i, events) in blocks.into_iter().enumerate() {
    shim.make_block(u64::try_from(i).unwrap(), events).await;
  }

  let mut task = task_test.task();
  TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

  verify_db_invariants(&task_test.db, &task_test.serai, num_blocks).await;
}
