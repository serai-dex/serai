use blake2::Digest as _;
use rand::RngCore as _;
use serai_db::test_helpers::{ChannelDrainAsserter, VerifyDbInvariants};
use serai_primitives::crypto::EmbeddedEllipticCurveKeys as AuxiliaryKeysStruct;
use serai_mock_rpc::events::validator_sets as vset_events;

use crate::{intend::*, tests::*, *, AuxiliaryKeys, PendingValidators};

struct IntendTestStruct {
  serai: Arc<Serai>,
  db: MemDb,
}

impl_serai_task_test_struct!(IntendTestStruct);

impl IntoTask for IntendTestStruct {
  type Task = CosignIntendTask<MemDb>;

  fn task(&self) -> Self::Task {
    CosignIntendTask { db: self.db.clone(), serai: self.serai.clone() }
  }
}

impl IntoMockSerai for IntendTestStruct {}

#[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
const ITEMS_TO_PROCESS_AT_ONCE: usize =
  CosignIntendTask::<MemDb>::ITEMS_TO_PROCESS_AT_ONCE as usize;
// adds at least 1 item to go over the item count
const FUZZ_COUNT: usize = ITEMS_TO_PROCESS_AT_ONCE + 1;

struct ReplayState {
  stakes: HashMap<(ExternalNetworkId, SeraiAddress), u64>,
  latest_set: HashMap<ExternalNetworkId, NetworksCosigningSet>,
  auxiliary_keys: HashMap<(NetworkId, SeraiAddress), AuxiliaryKeysStruct>,
  decided_validators: HashMap<ExternalValidatorSet, Vec<SeraiAddress>>,
  next_session: HashMap<ExternalNetworkId, u32>,
  set_keys_count: usize,
  processed_set_keys: Vec<ExternalValidatorSet>,
  expected_block_hashes: HashMap<u64, BlockHash>,
  expected_builds_upon: serai_primitives::merkle::IncrementalUnbalancedMerkleTree,
  expected_global_sessions: Vec<(GlobalCosigningSessionId, GlobalCosigningSession)>,
  expected_ending_sessions: Vec<(GlobalCosigningSessionId, u64)>,
  expected_block_events: Vec<BlockEventData>,
  expected_intended_cosigns: HashMap<ExternalValidatorSet, Vec<CosignIntent>>,
  latest_global_session_intended: Option<GlobalCosigningSessionId>,
}

impl ReplayState {
  fn new() -> Self {
    Self {
      stakes: HashMap::new(),
      latest_set: HashMap::new(),
      auxiliary_keys: HashMap::new(),
      decided_validators: HashMap::new(),
      next_session: HashMap::new(),
      set_keys_count: 0,
      processed_set_keys: Vec::new(),
      expected_block_hashes: HashMap::new(),
      expected_builds_upon: serai_primitives::merkle::IncrementalUnbalancedMerkleTree::new(),
      expected_global_sessions: Vec::new(),
      expected_ending_sessions: Vec::new(),
      expected_block_events: Vec::new(),
      expected_intended_cosigns: HashMap::new(),
      latest_global_session_intended: None,
    }
  }

  fn current_sets_and_keys(&self) -> Vec<(ExternalValidatorSet, Public, Amount)> {
    ExternalNetworkId::all()
      .filter_map(|network| {
        let set = self.latest_set.get(&network)?;
        Some((ExternalValidatorSet { network, session: set.session }, set.key, set.stake))
      })
      .collect()
  }
}

struct IntendDbInvariantVerifier;
impl IntendDbInvariantVerifier {
  fn assert_channel_global_sessions(
    db: &mut MemDb,
    expected_global_sessions: &[(GlobalCosigningSessionId, GlobalCosigningSession)],
  ) {
    use serai_env::log::debug;

    let channel_global_sessions =
      ChannelDrainAsserter::drain_all(db, |txn| GlobalCosigningSessionsChannel::try_recv(txn));

    debug!(
      "GlobalCosigningSessionsChannel: got {} entries, expected {}",
      channel_global_sessions.len(),
      expected_global_sessions.len()
    );
    assert_eq!(
      channel_global_sessions.len(),
      expected_global_sessions.len(),
      "GlobalCosigningSessionsChannel count mismatch: got {}, expected {}",
      channel_global_sessions.len(),
      expected_global_sessions.len()
    );

    for (i, (channel_item, expected_item)) in
      channel_global_sessions.iter().zip(expected_global_sessions.iter()).enumerate()
    {
      debug!(
        "GlobalCosigningSessionsChannel[{i}]: session_id={}…",
        hex::encode(&channel_item.0[.. 8])
      );
      assert_eq!(
        channel_item.0, expected_item.0,
        "GlobalCosigningSessionsChannel[{i}] session_id mismatch"
      );
      let (channel_session, expected_session) = (&channel_item.1, &expected_item.1);

      let GlobalCosigningSession {
        start_block_number,
        cosigning_sets: sets,
        keys,
        stakes,
        total_stake,
      } = channel_session;
      let GlobalCosigningSession {
        start_block_number: expected_start_block_number,
        cosigning_sets: expected_sets,
        keys: expected_keys,
        stakes: expected_stakes,
        total_stake: expected_total_stake,
      } = expected_session;

      debug!(
        "GlobalCosigningSessionsChannel[{i}]: start_block_number={start_block_number}, \
         sets={sets:?}, keys={keys:?}, stakes={stakes:?}, total_stake={total_stake}"
      );
      assert_eq!(
        start_block_number, expected_start_block_number,
        "GlobalCosigningSessionsChannel[{i}] start_block_number mismatch"
      );
      assert_eq!(sets, expected_sets, "GlobalCosigningSessionsChannel[{i}] sets mismatch");
      assert_eq!(keys, expected_keys, "GlobalCosigningSessionsChannel[{i}] keys mismatch");
      assert_eq!(stakes, expected_stakes, "GlobalCosigningSessionsChannel[{i}] stakes mismatch");
      assert_eq!(
        total_stake, expected_total_stake,
        "GlobalCosigningSessionsChannel[{i}] total_stake mismatch"
      );
    }
  }

  fn assert_channel_block_events(db: &mut MemDb, expected_block_events: &[BlockEventData]) {
    use serai_env::log::debug;

    let channel_block_events =
      ChannelDrainAsserter::drain_all(db, |txn| BlockEvents::try_recv(txn));

    debug!(
      "BlockEvents channel: got {} entries, expected {}",
      channel_block_events.len(),
      expected_block_events.len()
    );
    assert_eq!(
      channel_block_events.len(),
      expected_block_events.len(),
      "BlockEvents count mismatch: got {}, expected {}",
      channel_block_events.len(),
      expected_block_events.len()
    );

    for (i, (channel_item, expected_item)) in
      channel_block_events.iter().zip(expected_block_events.iter()).enumerate()
    {
      let BlockEventData { block_number, has_events } = channel_item;
      let BlockEventData { block_number: expected_block_number, has_events: expected_has_events } =
        expected_item;

      debug!("BlockEvents[{i}]: block #{block_number}, has_events={has_events:?}");
      assert_eq!(block_number, expected_block_number, "BlockEvents[{i}] block_number mismatch");
      assert_eq!(
        has_events, expected_has_events,
        "BlockEvents[{i}] has_events mismatch for block {expected_block_number}"
      );
    }
  }

  fn assert_channel_intended_cosigns(
    db: &mut MemDb,
    expected_intended_cosigns: &HashMap<ExternalValidatorSet, Vec<CosignIntent>>,
  ) {
    use serai_env::log::debug;

    let drained = ChannelDrainAsserter::drain_keys(
      db,
      expected_intended_cosigns.keys().copied(),
      |set, txn| NetworksIntendedCosigns::try_recv(txn, *set),
    );

    for (set, expected_intents) in expected_intended_cosigns {
      let Some(channel_intents) = drained.get(set) else {
        panic!("drained map missing key {set:?} (drained {} sets)", drained.len());
      };

      debug!(
        "IntendedCosigns[{set:?}]: got {} entries, expected {}",
        channel_intents.len(),
        expected_intents.len()
      );
      assert_eq!(
        channel_intents.len(),
        expected_intents.len(),
        "IntendedCosigns count mismatch: got {}, expected {}",
        channel_intents.len(),
        expected_intents.len()
      );

      for (i, (channel_intent, expected_intent)) in
        channel_intents.iter().zip(expected_intents.iter()).enumerate()
      {
        let CosignIntent {
          global_cosigning_session: global_session,
          block_number,
          block_hash,
          notable,
        } = channel_intent;
        let CosignIntent {
          global_cosigning_session: expected_global_session,
          block_number: expected_block_number,
          block_hash: expected_block_hash,
          notable: expected_notable,
        } = expected_intent;

        debug!(
          "IntendedCosigns[{set:?}][{i}]: global_session={}…, \
           block #{block_number}, hash={}…, notable={notable}",
          hex::encode(&global_session[.. 8]),
          hex::encode(&block_hash.0[.. 8]),
        );
        assert_eq!(
          global_session, expected_global_session,
          "IntendedCosigns[{set:?}][{i}] global_session mismatch"
        );
        assert_eq!(
          block_number, expected_block_number,
          "IntendedCosigns[{set:?}][{i}] block_number mismatch"
        );
        assert_eq!(
          block_hash, expected_block_hash,
          "IntendedCosigns[{set:?}][{i}] block_hash mismatch"
        );
        assert_eq!(notable, expected_notable, "IntendedCosigns[{set:?}][{i}] notable mismatch");
      }
    }
  }

  fn assert_expected_db_state(db: &mut MemDb, state: &ReplayState) {
    use serai_env::log::debug;

    let num_blocks = state.expected_block_events.len();
    let num_blocks_u64 = u64::try_from(num_blocks).unwrap();
    let no_blocks_processed = num_blocks == 0;

    let scan_from = ScanIntendBlocksFrom::get(db);
    debug!("ScanCosignFrom: {scan_from:?}");

    if no_blocks_processed {
      assert_eq!(scan_from, None, "ScanCosignFrom should be None before any blocks are processed");
      assert!(
        BuildsUpon::get(db).is_none(),
        "BuildsUpon should be absent before any blocks are processed"
      );
      assert!(
        SubstrateBlockHash::get(db, 0).is_none(),
        "SubstrateBlockHash should be absent before any blocks are processed"
      );

      let mut txn = db.txn();
      assert!(GlobalCosigningSessionsChannel::try_recv(&mut txn).is_none());
      assert!(BlockEvents::try_recv(&mut txn).is_none());
      assert!(LatestGlobalCosigningSessionIntended::get(db).is_none());
      return;
    }

    assert_eq!(
      scan_from,
      Some(num_blocks_u64),
      "ScanCosignFrom should be {num_blocks} after processing blocks 0..={} ",
      num_blocks - 1
    );

    debug!("BuildsUpon: {:?}", BuildsUpon::get(db).unwrap());
    assert_eq!(
      BuildsUpon::get(db),
      Some(state.expected_builds_upon.clone()),
      "BuildsUpon merkle tree mismatch"
    );

    for (&(network, validator), expected_keys) in &state.auxiliary_keys {
      let db_keys = AuxiliaryKeys::get(db, network, validator);

      debug!("AuxiliaryKeys[({network:?}, {validator:?})]: {db_keys:?}");
      assert_eq!(
        &db_keys
          .unwrap_or_else(|| panic!("AuxiliaryKeys should exist for ({network:?}, {validator:?})")),
        expected_keys,
        "AuxiliaryKeys mismatch for ({network:?}, {validator:?})"
      );
    }

    for (&(network, validator), &expected_amount) in &state.stakes {
      let db_stake = Stakes::get(db, network, crate::serai_networks_auxiliary_key(db, validator));

      debug!("Stakes[({network:?}, {validator:?})]: {db_stake:?} (expected {expected_amount})");
      assert_eq!(
        db_stake,
        Some(Amount(expected_amount)),
        "stake mismatch for ({network:?}, {validator:?}): \
         db={db_stake:?}, expected={expected_amount}"
      );
    }

    for (&network, &session_num) in &state.next_session {
      let expected = state.latest_set.get(&network);
      let latest_set = NetworksLatestSet::get(db, network);

      debug!("LatestSet[{network:?}]: {latest_set:?}");
      if let Some(expected_set) = expected {
        let latest = latest_set.unwrap_or_else(|| panic!("LatestSet should exist for {network:?}"));
        let NetworksCosigningSet { session, key, stake } = &latest;
        let NetworksCosigningSet {
          session: expected_session,
          key: expected_key,
          stake: expected_stake,
        } = expected_set;

        assert_eq!(session, expected_session, "LatestSet session mismatch for {network:?}");
        assert_eq!(key, expected_key, "LatestSet session mismatch for {network:?}");
        assert_eq!(stake.0, expected_stake.0, "LatestSet stake mismatch for {network:?}");
      } else if session_num > 0 {
        assert!(latest_set.is_none(), "LatestSet should be None for {network:?}");
      }
    }

    for (&block_number, expected_hash) in &state.expected_block_hashes {
      let stored = SubstrateBlockHash::get(db, block_number);
      debug!("SubstrateBlockHash[#{block_number}]: {stored:?}");
      assert_eq!(
        stored,
        Some(*expected_hash),
        "SubstrateBlockHash mismatch for block #{block_number}: \
         db={stored:?}, expected={expected_hash:?}",
      );
    }

    for processed_set in &state.processed_set_keys {
      let pending_validators = PendingValidators::get(db, *processed_set);
      debug!("PendingValidators[{processed_set:?}]: {pending_validators:?}");
      assert!(
        pending_validators.is_none(),
        "PendingValidators should be cleared after SetKeys for {processed_set:?}, \
         got {pending_validators:?}"
      );
    }

    // Build deduplicated maps (last value wins) for DB verification
    let mut db_expected_sessions: HashMap<GlobalCosigningSessionId, &GlobalCosigningSession> =
      HashMap::new();
    for (id, session) in &state.expected_global_sessions {
      db_expected_sessions.insert(*id, session);
    }
    let mut db_expected_endings: HashMap<GlobalCosigningSessionId, u64> = HashMap::new();
    for (id, block) in &state.expected_ending_sessions {
      db_expected_endings.insert(*id, *block);
    }

    for (session_id, expected) in &db_expected_sessions {
      let stored = GlobalCosigningSessions::get(db, *session_id)
        .unwrap_or_else(|| panic!("GlobalSessions[{}] should exist", hex::encode(session_id)));
      let GlobalCosigningSession {
        start_block_number,
        cosigning_sets: sets,
        keys,
        stakes,
        total_stake,
      } = &stored;
      let sum: u64 = stakes.values().sum();

      debug!(
        "GlobalSessions[{}]: start_block_number={}, sets={:?}, total_stake={}",
        hex::encode(session_id),
        start_block_number,
        sets,
        total_stake,
      );
      assert_eq!(
        *total_stake,
        sum,
        "GlobalSessions[{}] total_stake ({}) should equal sum of individual stakes ({sum})",
        hex::encode(session_id),
        total_stake,
      );
      assert_eq!(
        *start_block_number,
        expected.start_block_number,
        "GlobalSessions[{}] start_block_number mismatch: db={start_block_number}, \
         expected={}",
        hex::encode(session_id),
        expected.start_block_number,
      );
      assert_eq!(
        sets,
        &expected.cosigning_sets,
        "GlobalSessions[{}] sets mismatch",
        hex::encode(session_id)
      );
      assert_eq!(keys, &expected.keys, "GlobalSessions[{}] keys mismatch", hex::encode(session_id));
      assert_eq!(
        stakes,
        &expected.stakes,
        "GlobalSessions[{}] stakes mismatch",
        hex::encode(session_id),
      );
      assert_eq!(
        *total_stake,
        expected.total_stake,
        "GlobalSessions[{}] total_stake mismatch: db={total_stake}, expected={}",
        hex::encode(session_id),
        expected.total_stake,
      );
    }

    for (session_id, expected_last_block) in &db_expected_endings {
      let stored = GlobalCosigningSessionsLastBlock::get(db, *session_id);

      debug!("GlobalSessionsLastBlock[{}]: {stored:?}", hex::encode(session_id));
      assert_eq!(
        stored,
        Some(*expected_last_block),
        "GlobalSessionsLastBlock[{}] mismatch: db={stored:?}, expected={expected_last_block}",
        hex::encode(session_id),
      );
    }

    let latest_session_id = LatestGlobalCosigningSessionIntended::get(db);

    debug!("LatestGlobalSessionIntended: {:?}", latest_session_id.map(hex::encode));
    assert_eq!(
      latest_session_id, state.latest_global_session_intended,
      "LatestGlobalSessionIntended should be the latest expected session: \
         db={latest_session_id:?}, expected={:?}",
      state.latest_global_session_intended
    );

    serai_env::info!(
      "DB invariants verified: {} blocks, {} stake entries, {} LatestSets, {} SetKeys events",
      num_blocks,
      state.stakes.len(),
      state.latest_set.len(),
      state.set_keys_count
    );
  }
}

impl VerifyDbInvariants for IntendDbInvariantVerifier {
  type State = ReplayState;

  async fn replay_block(state: &mut ReplayState, serai: &Serai, block_num: u64) {
    let block = serai.block_by_number(block_num).await.unwrap().unwrap();
    let serai_block_hash = block.header.hash();
    let serai_block_events = serai.events(serai_block_hash).await.unwrap();

    state.expected_block_hashes.insert(block_num, serai_block_hash);
    state.expected_builds_upon.append(
      abi::BLOCK_BRANCH_TAG,
      blake2::Blake2b256::new_with_prefix([abi::BLOCK_LEAF_TAG])
        .chain_update(serai_block_hash.0)
        .finalize()
        .into(),
    );

    let validator_set_events = serai_block_events.validator_sets();

    for event in validator_set_events.set_embedded_elliptic_curve_keys_events() {
      let Event::SetEmbeddedEllipticCurveKeys { validator, keys } = &event else { continue };
      state.auxiliary_keys.insert((keys.network(), *validator), *keys);
    }

    for event in validator_set_events.allocation_events() {
      let Event::Allocation { validator, network, amount } = event else { continue };
      let Ok(net) = ExternalNetworkId::try_from(*network) else { continue };
      *state.stakes.entry((net, *validator)).or_insert(0) += amount.0;
    }
    for event in validator_set_events.deallocation_events() {
      let Event::Deallocation { validator, network, amount: deallocating_amount, .. } = event
      else {
        continue;
      };
      let Ok(net) = ExternalNetworkId::try_from(*network) else { continue };
      if state.stakes.contains_key(&(net, *validator)) {
        let entry = state.stakes.entry((net, *validator)).or_insert(0);
        *entry -= deallocating_amount.0;
        if *entry == 0 {
          // 0 stake is stored as None
          state.stakes.remove(&(net, *validator));
        }
      } else if deallocating_amount.0 != 0 {
        panic!("fuzzer invariant: deallocation event without existing stake")
      }
      // } else <- There is no else case because if deallocating 0, and has no existing stake
      // this is valid but nothing changes
    }

    for event in validator_set_events.set_decided_events() {
      let Event::SetDecided { set, validators } = event else { continue };
      let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };
      state.decided_validators.insert(set, validators.iter().map(|(v, _)| *v).collect());
    }

    let mut has_events = HasEvents::No;
    for event in validator_set_events.set_keys_events() {
      let Event::SetKeys { set, key_pair } = event else { continue };
      let set = *set;

      state.latest_set.remove(&set.network);

      let validators = state.decided_validators.remove(&set).unwrap_or_default();
      let stake: u64 =
        validators.iter().map(|v| state.stakes.get(&(set.network, *v)).copied().unwrap_or(0)).sum();

      // During bootstrap (pre-economic-security), SetKeys carry 0 stake
      // because no SRI Allocation events have occurred yet. We still count
      // them as valid session progression. Only skip SetKeys with 0 stake
      // when a prior set on this network already had stake.
      let had_stake_before = state.latest_set.get(&set.network).is_some_and(|s| s.stake.0 > 0);

      if !had_stake_before || stake > 0 {
        state.set_keys_count += 1;
        state.processed_set_keys.push(set);
      }

      if stake > 0 {
        has_events = has_events.max(HasEvents::Notable);
        state.latest_set.insert(
          set.network,
          NetworksCosigningSet { session: set.session, key: key_pair.0, stake: Amount(stake) },
        );
      }
      *state.next_session.entry(set.network).or_insert(0) += 1;
    }

    for event in validator_set_events.slashes_events() {
      let Event::Slashes(abi::validator_sets::ReportedSlashes::ExternalValidatorSet(set)) = event
      else {
        continue;
      };
      state.latest_set.remove(&set.network);
    }

    if serai_block_events.coins().burn_with_instruction_events().next().is_some() {
      has_events = has_events.max(HasEvents::NonNotable);
    }

    let global_session_for_this_block = state.latest_global_session_intended;
    let sets_and_keys = state.current_sets_and_keys();

    // if no cosigning sets exist, reset has_events
    if sets_and_keys.is_empty() {
      has_events = HasEvents::No;
    }

    if has_events == HasEvents::Notable {
      let new_global_session_id =
        GlobalCosigningSession::id(sets_and_keys.iter().map(|(set, _, _)| *set).collect());

      let mut cosigning_sets = Vec::with_capacity(sets_and_keys.len());
      let mut keys = HashMap::with_capacity(sets_and_keys.len());
      let mut stakes_map = HashMap::with_capacity(sets_and_keys.len());
      let mut total_stake = 0u64;
      for (set, key, stake) in sets_and_keys {
        cosigning_sets.push(set);
        keys.insert(set.network, key);
        stakes_map.insert(set.network, stake.0);
        total_stake += stake.0;
      }

      state.expected_global_sessions.push((
        new_global_session_id,
        GlobalCosigningSession {
          start_block_number: block_num + 1,
          cosigning_sets,
          keys,
          stakes: stakes_map,
          total_stake,
        },
      ));
      if let Some(prior_session_id) = global_session_for_this_block {
        state.expected_ending_sessions.push((prior_session_id, block_num));
      }
      state.latest_global_session_intended = Some(new_global_session_id);

      if let Some(prior_session_id) = global_session_for_this_block {
        if let Some((_, prior_session)) =
          state.expected_global_sessions.iter().find(|(id, _)| *id == prior_session_id)
        {
          for &set in &prior_session.cosigning_sets {
            state.expected_intended_cosigns.entry(set).or_default().push(CosignIntent {
              global_cosigning_session: prior_session_id,
              block_number: block_num,
              block_hash: serai_block_hash,
              notable: true,
            });
          }
        }
      }
    } else if has_events == HasEvents::NonNotable {
      if let Some(session_id) = global_session_for_this_block {
        if let Some((_, session)) =
          state.expected_global_sessions.iter().find(|(id, _)| *id == session_id)
        {
          for &set in &session.cosigning_sets {
            state.expected_intended_cosigns.entry(set).or_default().push(CosignIntent {
              global_cosigning_session: session_id,
              block_number: block_num,
              block_hash: serai_block_hash,
              notable: false,
            });
          }
        }
      }
    }

    if global_session_for_this_block.is_none() {
      has_events = HasEvents::No;
    }

    state.expected_block_events.push(BlockEventData { block_number: block_num, has_events });
  }

  async fn verify_db_invariants(db: &mut MemDb, state: &ReplayState) {
    Self::assert_expected_db_state(db, state);
    Self::assert_channel_global_sessions(db, &state.expected_global_sessions);
    Self::assert_channel_block_events(db, &state.expected_block_events);
    Self::assert_channel_intended_cosigns(db, &state.expected_intended_cosigns);
  }
}

/// Convenience function: replay blocks then verify invariants.
async fn verify_db_invariants(db: &mut MemDb, serai: &Serai, num_blocks: u64) {
  let mut state = ReplayState::new();
  IntendDbInvariantVerifier::replay_blocks(&mut state, serai, num_blocks).await;
  IntendDbInvariantVerifier::verify_db_invariants(db, &state).await;
}

mod errors {
  use super::*;

  #[tokio::test]
  async fn handles_rpc_error_on_latest_finalized() {
    let rng = new_test_rng();
    let (mock_serai, mut task_test) = IntendTestStruct::setup_mock_test().await;

    let mut fuzzer = BlockEventsFuzzer::new(rng);
    mock_serai.fuzz_blocks_up_to(&mut fuzzer, FUZZ_COUNT).await;
    mock_serai.set_error("blockchain/latest_finalized_block_number", "").await;
    mock_serai.fuzz_blocks_up_to(&mut fuzzer, FUZZ_COUNT).await;

    {
      let mut task = task_test.task();
      TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching latest finalized").await;
    }
    verify_db_invariants(&mut task_test.db, &task_test.serai, 0).await;

    mock_serai.clear_all_errors().await;
    {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    verify_db_invariants(&mut task_test.db, &task_test.serai, mock_serai.next_block().await).await;
  }

  #[tokio::test]
  async fn handles_rpc_error_on_block_fetch() {
    let rng = new_test_rng();
    let (mock_serai, mut task_test) = IntendTestStruct::setup_mock_test().await;

    let mut fuzzer = BlockEventsFuzzer::new(rng);
    mock_serai.fuzz_blocks_up_to(&mut fuzzer, FUZZ_COUNT).await;

    let failure_block_number = mock_serai.last_block().await;
    mock_serai.set_block_number_error("blockchain/block", failure_block_number, "").await;
    mock_serai.fuzz_blocks_up_to(&mut fuzzer, FUZZ_COUNT).await;

    {
      let mut task = task_test.task();
      TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching block").await;
    }
    verify_db_invariants(&mut task_test.db, &task_test.serai, failure_block_number).await;

    mock_serai.clear_all_errors().await;
    {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    verify_db_invariants(&mut task_test.db, &task_test.serai, mock_serai.next_block().await).await;
  }

  #[tokio::test]
  async fn panics_if_finalized_block_is_not_returned() {
    let rng = new_test_rng();
    let (mock_serai, mut task_test) = IntendTestStruct::setup_mock_test().await;

    let mut fuzzer = BlockEventsFuzzer::new(rng);
    mock_serai.fuzz_blocks_up_to(&mut fuzzer, ITEMS_TO_PROCESS_AT_ONCE).await;

    let panic_block_number = mock_serai.last_block().await;
    mock_serai.set_block_missing(panic_block_number).await;
    mock_serai.fuzz_blocks_up_to(&mut fuzzer, ITEMS_TO_PROCESS_AT_ONCE).await;

    {
      let mut task = task_test.task();
      TaskTest::task_runs_and_panics_with(
        &mut task,
        &format!("couldn't get block #{panic_block_number} which should've been finalized"),
      )
      .await;
    }
    let blocks_iterated =
      if usize::try_from(panic_block_number).unwrap() <= ITEMS_TO_PROCESS_AT_ONCE {
        0
      } else {
        panic_block_number
      };
    verify_db_invariants(&mut task_test.db, &task_test.serai, blocks_iterated).await;
  }

  #[tokio::test]
  async fn handles_rpc_error_on_events_fetch() {
    let rng = new_test_rng();
    let (mock_serai, mut task_test) = IntendTestStruct::setup_mock_test().await;

    let mut fuzzer = BlockEventsFuzzer::new(rng);
    mock_serai.fuzz_blocks_up_to(&mut fuzzer, FUZZ_COUNT).await;

    let failure_block_number = mock_serai.last_block().await;
    mock_serai.set_block_number_error("blockchain/events", failure_block_number, "").await;
    mock_serai.fuzz_blocks_up_to(&mut fuzzer, FUZZ_COUNT).await;

    {
      let mut task = task_test.task();
      TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching events").await;
    }
    verify_db_invariants(&mut task_test.db, &task_test.serai, failure_block_number).await;

    mock_serai.clear_all_errors().await;
    {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    verify_db_invariants(&mut task_test.db, &task_test.serai, mock_serai.next_block().await).await;
  }

  #[tokio::test]
  async fn panics_if_chain_is_not_linear() {
    let rng = new_test_rng();
    let (mock_serai, mut task_test) = IntendTestStruct::setup_mock_test().await;

    let mut fuzzer = BlockEventsFuzzer::new(rng);
    mock_serai.fuzz_blocks_up_to(&mut fuzzer, FUZZ_COUNT).await;

    let panic_block_number = mock_serai.next_block().await;
    mock_serai.make_non_linear_block(panic_block_number, vec![]).await;
    mock_serai.fuzz_blocks_up_to(&mut fuzzer, FUZZ_COUNT).await;

    {
      let mut task = task_test.task();
      TaskTest::task_runs_and_panics_with(
        &mut task,
        &format!(
          "node's block #{} doesn't build upon the block #{} prior indexed",
          panic_block_number,
          panic_block_number - 1
        ),
      )
      .await;
    }
    verify_db_invariants(&mut task_test.db, &task_test.serai, panic_block_number).await;
  }

  #[tokio::test]
  async fn panics_if_set_decided_has_empty_validators() {
    let mut rng = new_test_rng();
    let (mock_serai, mut task_test) = IntendTestStruct::setup_mock_test().await;

    let mut fuzzer = BlockEventsFuzzer::new(rng.clone());
    mock_serai.fuzz_blocks_up_to(&mut fuzzer, FUZZ_COUNT - 1).await;

    let panic_block_number = mock_serai.next_block().await;
    let empty_set_decided = vset_events::set_decided(
      ValidatorSet {
        network: NetworkId::External(random_external_network_id(&mut rng)),
        session: Session(0),
      },
      vec![],
    );
    mock_serai.add_block_with_events(vec![vec![empty_set_decided]]).await;
    mock_serai.fuzz_blocks_up_to(&mut fuzzer, FUZZ_COUNT).await;

    {
      let mut task = task_test.task();
      TaskTest::task_runs_and_panics_with(
        &mut task,
        "validator set from Event::SetDecided was empty",
      )
      .await;
    }
    verify_db_invariants(&mut task_test.db, &task_test.serai, panic_block_number).await;
  }
}

mod progresses {
  use super::*;

  #[tokio::test]
  async fn indexes_by_serai_network_auxiliary_keys() {
    let mut rng = new_test_rng();
    let external_network_id = random_external_network_id(&mut rng);

    let validator = random_serai_address(&mut rng);
    let serai_embedded_elliptic_curve_keys = random_serai_embedded_elliptic_curve_keys(&mut rng);
    let external_networks_embedded_elliptic_curve_keys =
      random_embedded_elliptic_curve_keys(&mut rng, NetworkId::External(external_network_id));

    let (mock_serai, mut task_test) = IntendTestStruct::setup_mock_test_with_validator(
      validator,
      &[serai_embedded_elliptic_curve_keys, external_networks_embedded_elliptic_curve_keys],
    )
    .await;

    const ALLOCATION: u64 = 1000;
    const DEALLOCATION: u64 = 400;

    mock_serai
      .add_block_with_events(vec![vec![vset_events::allocation(
        validator,
        NetworkId::External(external_network_id),
        ALLOCATION,
      )]])
      .await;
    mock_serai
      .add_block_with_events(vec![vec![vset_events::deallocation(
        validator,
        NetworkId::External(external_network_id),
        DEALLOCATION,
      )]])
      .await;

    {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    verify_db_invariants(&mut task_test.db, &task_test.serai, mock_serai.next_block().await).await;

    {
      let stored_external_keys =
        AuxiliaryKeys::get(&task_test.db, NetworkId::External(external_network_id), validator)
          .expect("NetworkId::External auxiliary keys should exist for validator");
      assert_eq!(
        stored_external_keys, external_networks_embedded_elliptic_curve_keys,
        "NetworkId::External auxiliary keys mismatch"
      );
    }

    let AuxiliaryKeysStruct::Serai(serai_key_bytes) = serai_embedded_elliptic_curve_keys else {
      unreachable!("serai_keys was not AuxiliaryKeysStruct::Serai(..)")
    };
    let expected_validator_auxiliary_key =
      serai_primitives::crypto::SeraiNetworksAuxiliaryKey::from_bytes(serai_key_bytes)
        .expect("invalid serai key bytes");

    let stored_serai_network_auxiliary_key =
      crate::serai_networks_auxiliary_key(&task_test.db, validator);

    {
      assert_eq!(
        stored_serai_network_auxiliary_key, expected_validator_auxiliary_key,
        "The validator auxiliary key should match the entry for the NetworkId::Serai auxiliary key"
      );
    }

    {
      const EXPECTED_STAKE: u64 = ALLOCATION - DEALLOCATION;
      let stored_stake =
        Stakes::get(&task_test.db, external_network_id, expected_validator_auxiliary_key);
      assert_eq!(
        stored_stake,
        Some(Amount(EXPECTED_STAKE)),
        "Stake should be stored under NetworkId::Serai's validator auxiliary key"
      );
    }

    // Also test NetworksPendingValidators
    {
      const SESSION: u32 = 0;
      let set = ExternalValidatorSet { network: external_network_id, session: Session(SESSION) };

      mock_serai
        .add_block_with_events(vec![vec![vset_events::set_decided(
          set.into(),
          vec![(validator, KeyShares::ONE)],
        )]])
        .await;

      {
        let mut task = task_test.task();
        TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
      }
      verify_db_invariants(&mut task_test.db, &task_test.serai, mock_serai.next_block().await)
        .await;

      let stored_pending = NetworksPendingValidators::get(&task_test.db, set)
        .expect("NetworksPendingValidators should exist for the decided set");
      assert_eq!(
        stored_pending,
        vec![expected_validator_auxiliary_key],
        "NetworksPendingValidators should contain the validator's SeraiNetworksAuxiliaryKey"
      );
    }
  }

  #[tokio::test]
  async fn deallocating_zero_is_a_noop() {
    let mut rng = new_test_rng();
    let network = random_external_network_id(&mut rng);
    let (validator, serai_auxiliary_keys, _) =
      random_validator_and_auxiliary_keys(&mut rng, network);

    {
      let (mock_serai, task_test) =
        IntendTestStruct::setup_mock_test_with_validator(validator, &[serai_auxiliary_keys]).await;

      // Allocate 0 stake to the validator
      mock_serai
        .add_block_with_events(vec![vec![vset_events::allocation(
          validator,
          NetworkId::External(network),
          0,
        )]])
        .await;
      // Deallocate 0 from the same validator
      mock_serai
        .add_block_with_events(vec![vec![vset_events::deallocation(
          validator,
          NetworkId::External(network),
          0,
        )]])
        .await;

      let mut task = task_test.task();
      {
        TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
      }

      // Verify it works and the stake is unchanged after the 0-deallocation
      let stake = Stakes::get(
        &task_test.db,
        network,
        crate::serai_networks_auxiliary_key(&task.db, validator),
      );
      // Adding 0 or removing 0 stake should keep its state as None
      assert_eq!(stake, None, "stake should be unchanged after deallocating 0");
    }

    {
      let (mock_serai, task_test) =
        IntendTestStruct::setup_mock_test_with_validator(validator, &[serai_auxiliary_keys]).await;

      let amount = rng.next_u64();
      // Allocate some stake to the validator
      mock_serai
        .add_block_with_events(vec![vec![vset_events::allocation(
          validator,
          NetworkId::External(network),
          amount,
        )]])
        .await;
      // Deallocate 0 from the same validator
      mock_serai
        .add_block_with_events(vec![vec![vset_events::deallocation(
          validator,
          NetworkId::External(network),
          0,
        )]])
        .await;

      let mut task = task_test.task();
      {
        TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
      }

      // Verify the 0-deallocation works and the stake is unchanged after it
      let stake = Stakes::get(
        &task_test.db,
        network,
        crate::serai_networks_auxiliary_key(&task.db, validator),
      );
      assert_eq!(stake, Some(Amount(amount)), "stake should be unchanged after deallocating 0");
    }

    {
      let (mock_serai, task_test) =
        IntendTestStruct::setup_mock_test_with_validator(validator, &[serai_auxiliary_keys]).await;

      // Deallocate 0 from a validator with no allocated stake
      mock_serai
        .add_block_with_events(vec![vec![vset_events::deallocation(
          validator,
          NetworkId::External(network),
          0,
        )]])
        .await;

      let mut task = task_test.task();
      {
        TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
      }

      let stake = Stakes::get(
        &task_test.db,
        network,
        crate::serai_networks_auxiliary_key(&task.db, validator),
      );
      assert_eq!(stake, None);
    }
  }

  #[tokio::test]
  async fn handles_notable_event_replaced_by_zero_stake_set() {
    let mut rng = new_test_rng();
    let network = random_external_network_id(&mut rng);
    let validator_with_stake = random_serai_address(&mut rng);
    let validator_without_stake = random_serai_address(&mut rng);

    let (mock_serai, mut task_test) = IntendTestStruct::setup_mock_test().await;

    // Block 0: NetworkId::Serai auxiliary keys for both validators
    mock_serai
      .add_block_with_events(vec![vec![
        vset_events::set_embedded_elliptic_curve_keys(
          validator_with_stake,
          random_embedded_elliptic_curve_keys(&mut rng, NetworkId::Serai),
        ),
        vset_events::set_embedded_elliptic_curve_keys(
          validator_without_stake,
          random_embedded_elliptic_curve_keys(&mut rng, NetworkId::Serai),
        ),
      ]])
      .await;

    // Block 1: Allocation for validator with stake + SetDecided for both sessions
    mock_serai
      .add_block_with_events(vec![vec![
        vset_events::allocation(validator_with_stake, NetworkId::External(network), 1000),
        vset_events::set_decided(
          ValidatorSet { network: NetworkId::External(network), session: Session(0) },
          vec![(validator_with_stake, KeyShares::ONE)],
        ),
        vset_events::set_decided(
          ValidatorSet { network: NetworkId::External(network), session: Session(1) },
          vec![(validator_without_stake, KeyShares::ONE)],
        ),
      ]])
      .await;

    let vset_session0_key_pair = random_vset_key_pair(&mut rng);
    let vset_session1_key_pair = random_vset_key_pair(&mut rng);

    // Block 2: two SetKeys in the same block for the same network
    //   1st: session 0 with stake > 0 = Notable, creates LatestSet
    //   2nd: session 1 with stake == 0 -> LatestSet::take, no re-insert
    //   After both: has_events == Notable but cosigning_sets is empty.
    mock_serai
      .add_block_with_events(vec![vec![
        vset_events::set_keys(
          ExternalValidatorSet { network, session: Session(0) },
          vset_session0_key_pair,
        ),
        vset_events::set_keys(
          ExternalValidatorSet { network, session: Session(1) },
          vset_session1_key_pair,
        ),
      ]])
      .await;

    // The task should gracefully skip session creation and mark the block
    // as HasEvents::No instead of panicking.
    {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }

    verify_db_invariants(&mut task_test.db, &task_test.serai, mock_serai.next_block().await).await;
  }

  #[tokio::test]
  async fn retires_set_after_slashes() {
    let mut rng = new_test_rng();
    let network = random_external_network_id(&mut rng);
    let validator = random_serai_address(&mut rng);
    let serai_keys = random_serai_embedded_elliptic_curve_keys(&mut rng);

    let (mock_serai, mut task_test) =
      IntendTestStruct::setup_mock_test_with_validator(validator, &[serai_keys]).await;

    const ALLOCATION: u64 = 1000;

    mock_serai
      .add_block_with_events(vec![vec![vset_events::allocation(
        validator,
        NetworkId::External(network),
        ALLOCATION,
      )]])
      .await;
    mock_serai
      .add_block_with_events(vec![vec![vset_events::set_decided(
        ValidatorSet { network: NetworkId::External(network), session: Session(0) },
        vec![(validator, KeyShares::ONE)],
      )]])
      .await;
    mock_serai
      .add_block_with_events(vec![vec![vset_events::set_keys(
        ExternalValidatorSet { network, session: Session(0) },
        random_vset_key_pair(&mut rng),
      )]])
      .await;

    {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    verify_db_invariants(&mut task_test.db, &task_test.serai, mock_serai.next_block().await).await;

    // Directly verify that session 0 is the latest cosigning set before the slash
    {
      let latest_set = NetworksLatestSet::get(&task_test.db, network)
        .expect("NetworksLatestSet should exist after SetKeys");
      assert_eq!(
        latest_set.session,
        Session(0),
        "session 0 should be the latest set before slashes"
      );
    }

    mock_serai
      .add_block_with_events(vec![vec![vset_events::slash_report(ExternalValidatorSet {
        network,
        session: Session(0),
      })]])
      .await;

    {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    verify_db_invariants(&mut task_test.db, &task_test.serai, mock_serai.next_block().await).await;

    {
      let latest_set = NetworksLatestSet::get(&task_test.db, network);
      assert!(
        latest_set.is_none(),
        "NetworksLatestSet should be None after slashes (set retired), got {latest_set:?}"
      );
    }
  }

  #[tokio::test]
  async fn fuzzed_event_processing() {
    let num_blocks = 100u64;

    let rng = new_test_rng();
    let mut event_fuzzer = BlockEventsFuzzer::new(rng);
    let blocks = event_fuzzer.generate_blocks_with_keygen(num_blocks);

    serai_env::log::info!(
      "Fuzz test: {} blocks, {} validators",
      num_blocks,
      event_fuzzer.validators.len()
    );

    let (mock_serai, mut task_test) = IntendTestStruct::setup_mock_test().await;
    for block_events in blocks {
      mock_serai.add_block_with_events(block_events).await;
    }

    {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }

    verify_db_invariants(&mut task_test.db, &task_test.serai, num_blocks).await;
  }
}
