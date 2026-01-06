use core::future::Future;
use std::{
  collections::{HashMap, HashSet},
  time::{SystemTime, UNIX_EPOCH},
};

use blake2::{Blake2b256, Digest};
use serai_db::{Db as _, DbTxn, MemDb};
use serai_task::ContinuallyRan;

use serai_client_serai::{
  Events,
  abi::{
    Block, Event, Header, HeaderV1, BLOCK_HEADER_BRANCH_TAG, BLOCK_HEADER_LEAF_TAG, coins,
    primitives::{
      BlockHash,
      address::{ExternalAddress, SeraiAddress},
      balance::{Amount, Balance, ExternalBalance},
      coin::{Coin, ExternalCoin},
      crypto::{ExternalKey, KeyPair, Public},
      instructions::{OutInstruction, OutInstructionWithBalance},
      merkle::{IncrementalUnbalancedMerkleTree, UnbalancedMerkleTree},
      network_id::{ExternalNetworkId, NetworkId},
      validator_sets::{ExternalValidatorSet, KeyShares, Session, ValidatorSet},
    },
    signals, validator_sets,
  },
};

use crate::{
  intend::{
    BlockEventData, BlockEvents, BuildsUpon, CosignIntendTask, GlobalSessionsChannel,
    IntendedCosigns, LatestSet, ScanCosignFrom, Set, Stakes, Validators,
  },
  tests::{IntoTask, Test},
  CosignIntent, GlobalSession, GlobalSessions, GlobalSessionsLastBlock, HasEvents,
  LatestGlobalSessionIntended, SeraiRpc, SubstrateBlockHash,
};

fn set_keys_event(set: ExternalValidatorSet) -> Event {
  Event::ValidatorSets(validator_sets::Event::SetKeys {
    set,
    key_pair: KeyPair(Public([0xff; 32]), ExternalKey(vec![0xff; 32].try_into().unwrap())),
  })
}

fn set_decided_event(set: ValidatorSet, validators: Vec<(SeraiAddress, KeyShares)>) -> Event {
  Event::ValidatorSets(validator_sets::Event::SetDecided { set, validators })
}

fn allocation_event(validator: SeraiAddress, network: NetworkId, amount: u64) -> Event {
  Event::ValidatorSets(validator_sets::Event::Allocation {
    validator,
    network,
    amount: Amount(amount),
  })
}

fn deallocation_event(validator: SeraiAddress, network: NetworkId, amount: u64) -> Event {
  Event::ValidatorSets(validator_sets::Event::Deallocation {
    validator,
    network,
    amount: Amount(amount),
    timeline: validator_sets::DeallocationTimeline::Immediate,
  })
}

fn burn_with_instruction_event(from: SeraiAddress) -> Event {
  Event::Coins(coins::Event::BurnWithInstruction {
    from,
    instruction: OutInstructionWithBalance {
      instruction: OutInstruction::Transfer(
        ExternalAddress::try_from(vec![1u8, 2u8, 3u8]).unwrap(),
      ),
      balance: ExternalBalance { coin: ExternalCoin::Bitcoin, amount: Amount(1) },
    },
  })
}

fn events_from_allocations(allocations: &[(SeraiAddress, ExternalNetworkId, u64)]) -> Vec<Event> {
  allocations
    .iter()
    .map(|(validator, network, amount)| {
      allocation_event(*validator, NetworkId::External(*network), *amount)
    })
    .collect()
}

#[derive(Clone)]
pub(crate) struct Serai {
  pub(crate) latest_finalized_error: Option<String>,
  pub(crate) block_by_number_error: HashMap<u64, String>,
  pub(crate) events_error: HashMap<BlockHash, String>,
  pub(crate) blocks_by_number: HashMap<u64, Block>,
  pub(crate) events_by_hash: HashMap<BlockHash, Events>,
  pub(crate) builds_upon: IncrementalUnbalancedMerkleTree,
  pub(crate) missing_blocks: HashSet<u64>,
}

impl Default for Serai {
  fn default() -> Self {
    Self {
      latest_finalized_error: None,
      block_by_number_error: HashMap::new(),
      events_error: HashMap::new(),
      blocks_by_number: HashMap::new(),
      events_by_hash: HashMap::new(),
      builds_upon: IncrementalUnbalancedMerkleTree::new(),
      missing_blocks: HashSet::new(),
    }
  }
}

impl Serai {
  pub(crate) fn set_latest_finalized_error(&mut self, error: &str) {
    self.latest_finalized_error = Some(error.to_string());
  }

  pub(crate) fn set_block_not_found(&mut self, block_number: u64) {
    self.missing_blocks.insert(block_number);
  }

  pub(crate) fn set_block_error(&mut self, block_number: u64, error: &str) {
    self.block_by_number_error.insert(block_number, error.to_string());
  }

  pub(crate) fn set_events_error(&mut self, block_hash: BlockHash, error: &str) {
    self.events_error.insert(block_hash, error.to_string());
  }

  pub(crate) fn make_block(&mut self, number: u64) -> BlockHash {
    let block = Block {
      header: Header::V1(HeaderV1 {
        number,
        builds_upon: self.builds_upon.clone().calculate(BLOCK_HEADER_BRANCH_TAG),
        unix_time_in_millis: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
          as u64,
        transactions_commitment: UnbalancedMerkleTree::EMPTY,
        events_commitment: UnbalancedMerkleTree::EMPTY,
        consensus_commitment: [0; 32],
      }),
      transactions: vec![],
    };

    let block_hash = block.header.hash();

    self.builds_upon.append(
      BLOCK_HEADER_BRANCH_TAG,
      Blake2b256::new_with_prefix([BLOCK_HEADER_LEAF_TAG])
        .chain_update(block_hash.0)
        .finalize()
        .into(),
    );

    self.blocks_by_number.insert(number, block);

    block_hash
  }

  pub(crate) fn set_events(&mut self, block_hash: BlockHash, events: Vec<Event>) {
    self.events_by_hash.insert(block_hash, Events::with(events));
  }
}

impl SeraiRpc for Serai {
  fn latest_finalized_block_number(&self) -> impl Send + Future<Output = Result<u64, String>> {
    let err = self.latest_finalized_error.clone();
    let latest = self.blocks_by_number.keys().copied().max().unwrap_or(0);
    async move {
      if let Some(e) = err {
        return Err(e);
      }
      Ok(latest)
    }
  }

  fn block_by_number(
    &self,
    block: u64,
  ) -> impl Send + Future<Output = Result<Option<Block>, String>> {
    let err = self.block_by_number_error.get(&block).cloned();
    let block_entry = self.blocks_by_number.get(&block).cloned();
    let is_missing = self.missing_blocks.contains(&block);

    async move {
      if let Some(e) = err {
        return Err(e);
      }
      if is_missing {
        return Ok(None);
      }
      Ok(block_entry)
    }
  }

  fn events(&self, block: BlockHash) -> impl Send + Future<Output = Result<Events, String>> {
    let err = self.events_error.get(&block).cloned();
    let events = self.events_by_hash.get(&block).cloned().unwrap_or_default();
    async move {
      if let Some(e) = err {
        return Err(e);
      }
      Ok(events)
    }
  }
}

pub(crate) struct IntendTest {
  pub(crate) serai: Serai,
  pub(crate) db: MemDb,
}

impl Default for IntendTest {
  fn default() -> Self {
    Self { serai: Serai::default(), db: MemDb::default() }
  }
}

impl IntoTask for IntendTest {
  type Task = CosignIntendTask<MemDb, Serai>;

  fn into_task(&self) -> Self::Task {
    CosignIntendTask { db: self.db.clone(), serai: self.serai.clone() }
  }
}

impl IntendTest {
  fn assert_substrate_block_hash_exists(&self, block_number: u64) -> BlockHash {
    let block_hash = SubstrateBlockHash::get(&self.db, block_number);
    assert!(block_hash.is_some(), "no substrate blockhash for block {block_number}");
    block_hash.expect("no substrate blockhash")
  }

  fn assert_no_global_sessions_channel(&self) {
    assert_eq!(GlobalSessionsChannel::peek(&self.db).is_none(), true);
  }

  fn assert_no_block_events(&self) {
    assert_eq!(BlockEvents::peek(&self.db).is_none(), true);
  }

  fn assert_no_substrate_block_hash(&self, block_number: u64) {
    let block_hash = SubstrateBlockHash::get(&self.db, block_number);
    assert!(block_hash.is_none(), "expected no substrate blockhash for block {block_number}");
  }

  fn assert_builds_upon_is_expected(&self, expected: &IncrementalUnbalancedMerkleTree) {
    assert_eq!(BuildsUpon::get(&self.db).as_ref(), Some(expected));
  }

  fn assert_no_builds_upon(&self) {
    assert_eq!(BuildsUpon::get(&self.db), None);
  }

  // Assert everything that changed or should have changed after a simple task iteration run with linear blocks
  // (substrate block hashes are set and builds upon is expected)
  fn assert_task_iteration_per_block(&self, block_number: u64) -> BlockHash {
    let block_hash = self.assert_substrate_block_hash_exists(block_number);
    self.assert_builds_upon_is_expected(&self.serai.builds_upon);
    block_hash
  }

  fn assert_task_iteration_per_block_clears(&self, block_number: u64) {
    self.assert_no_substrate_block_hash(block_number);
    self.assert_no_builds_upon();
  }

  fn assert_block_events_is_expected(&mut self, expected: BlockEventData) {
    let mut txn = self.db.txn();
    let actual = BlockEvents::try_recv(&mut txn);
    txn.commit();
    match actual {
      Some(a) => {
        assert_eq!(a.block_number, expected.block_number);
        assert_eq!(a.has_events, expected.has_events);
      }
      None => panic!("BlockEvents mismatch: got None, expected {:?}", expected),
    }
  }

  fn assert_scan_cosign_from_is_expected(&self, expected: u64) {
    assert_eq!(ScanCosignFrom::get(&self.db), Some(expected));
  }

  fn assert_no_scan_cosign_from(&self) {
    assert_eq!(ScanCosignFrom::get(&self.db), None);
  }

  // Assert everything that changed or should have changed after task iteration is ran per block
  // (BlockEventData points to current block and events, ScanCosignFrom is the next block)
  fn assert_task_iteration_per_block_concluded(
    &mut self,
    block_number: u64,
    has_events: HasEvents,
  ) {
    self.assert_block_events_is_expected(BlockEventData { block_number, has_events });
    self.assert_scan_cosign_from_is_expected(block_number + 1);
  }

  fn assert_task_iteration_per_block_with_no_events_ran(&mut self, block_number: u64) {
    self.assert_task_iteration_per_block(block_number);
    self.assert_task_iteration_per_block_concluded(block_number, HasEvents::No);
  }

  fn assert_task_iterations_with_no_events_ran(&mut self, start_block: u64, end_block: u64) {
    for block_number in start_block..=end_block {
      self.assert_task_iteration_per_block(block_number);
      self.assert_block_events_is_expected(BlockEventData {
        block_number,
        has_events: HasEvents::No,
      });
    }

    self.assert_scan_cosign_from_is_expected(end_block + 1);
  }

  /// Asserts that blocks were processed successfully up to (but not including) failed_block.
  /// Takes the expected `builds_upon` value (state after the last successful block was processed).
  fn assert_task_iterations_with_no_events_failed_at(
    &mut self,
    failed_block: u64,
    expected_builds_upon: &IncrementalUnbalancedMerkleTree,
  ) {
    let prev_builds_upon = self.serai.builds_upon.clone();

    self.serai.builds_upon = expected_builds_upon.clone();
    self.assert_task_iteration_per_block_with_no_events_ran(failed_block - 1);

    self.serai.builds_upon = prev_builds_upon;
  }

  fn assert_stakes_is_expected(
    &self,
    network: ExternalNetworkId,
    validator: SeraiAddress,
    expected: Option<Amount>,
  ) {
    assert_eq!(Stakes::get(&self.db, network, validator), expected);
  }

  fn assert_no_stakes(&self, network: ExternalNetworkId, validator: SeraiAddress) {
    assert_eq!(Stakes::get(&self.db, network, validator), None);
  }

  /// Asserts stakes match the accumulated totals from a slice of allocations.
  /// Groups by (network, validator) and sums amounts before asserting.
  fn assert_stakes_from_allocations_is_expected(
    &self,
    allocations: &[(SeraiAddress, ExternalNetworkId, u64)],
  ) {
    let mut expected: HashMap<(ExternalNetworkId, SeraiAddress), u64> = HashMap::new();
    for (validator, network, amount) in allocations {
      *expected.entry((*network, *validator)).or_default() += amount;
    }
    for ((network, validator), amount) in expected {
      self.assert_stakes_is_expected(network, validator, Some(Amount(amount)));
    }
  }

  fn assert_global_session(actual: &GlobalSession, expected: &GlobalSession) {
    assert_eq!(actual.start_block_number, expected.start_block_number);
    assert_eq!(actual.sets, expected.sets);
    assert_eq!(actual.keys, expected.keys);
    assert_eq!(actual.stakes, expected.stakes);
    assert_eq!(actual.total_stake, expected.total_stake);
  }

  fn assert_validators_is_expected(
    &self,
    set: ExternalValidatorSet,
    expected: Option<Vec<SeraiAddress>>,
  ) {
    assert_eq!(Validators::get(&self.db, set), expected);
  }

  fn assert_no_validators(&self, set: ExternalValidatorSet) {
    assert_eq!(Validators::get(&self.db, set), None);
  }

  fn assert_latest_set_is_expected(&self, network: ExternalNetworkId, expected: Option<&Set>) {
    let actual = LatestSet::get(&self.db, network);
    match (actual.as_ref(), expected) {
      (Some(a), Some(e)) => {
        assert_eq!(a.session, e.session);
        assert_eq!(a.key, e.key);
        assert_eq!(a.stake, e.stake);
      }
      (None, None) => {}
      _ => panic!("LatestSet mismatch for {:?}", network),
    }
  }

  fn assert_no_latest_set(&self, network: ExternalNetworkId) {
    assert_eq!(LatestSet::get(&self.db, network).is_none(), true);
  }

  fn assert_global_sessions_get(&self, session_id: [u8; 32], expected: Option<&GlobalSession>) {
    match (GlobalSessions::get(&self.db, session_id), expected) {
      (Some(ref actual), Some(exp)) => Self::assert_global_session(actual, exp),
      (None, None) => {}
      (actual, exp) => {
        panic!("GlobalSessions mismatch: got {:?}, expected {:?}", actual.is_some(), exp.is_some())
      }
    }
  }

  fn assert_global_sessions_last_block(&self, session_id: [u8; 32], expected: u64) {
    assert_eq!(GlobalSessionsLastBlock::get(&self.db, session_id), Some(expected));
  }

  fn assert_latest_global_session_intended(&self, expected: Option<[u8; 32]>) {
    assert_eq!(LatestGlobalSessionIntended::get(&self.db), expected);
  }

  fn assert_no_latest_global_session_intended(&self) {
    assert_eq!(LatestGlobalSessionIntended::get(&self.db), None);
  }

  fn assert_global_sessions_channel_peek(&self, expected: Option<&([u8; 32], GlobalSession)>) {
    let actual = GlobalSessionsChannel::peek(&self.db);
    match (actual.as_ref(), expected) {
      (Some((aid, asess)), Some((eid, esess))) => {
        assert_eq!(aid, eid);
        Self::assert_global_session(asess, esess);
      }
      (None, None) => {}
      _ => panic!(
        "GlobalSessionsChannel mismatch: got {:?}, expected {:?}",
        actual.is_some(),
        expected.is_some()
      ),
    }
  }

  fn assert_intended_cosigns_peek(&self, set: ExternalValidatorSet, expected: CosignIntent) {
    assert_eq!(IntendedCosigns::peek(&self.db, set), Some(expected));
  }

  fn assert_no_intended_cosigns(&self, set: ExternalValidatorSet) {
    assert_eq!(IntendedCosigns::peek(&self.db, set).is_none(), true);
  }

  /// Asserts that all DB entries are cleared (return None or are empty).
  /// This is useful for verifying initial state or that cleanup worked correctly.
  fn assert_db_cleared(
    &self,
    block_numbers: &[u64],
    networks: &[ExternalNetworkId],
    sets: &[ExternalValidatorSet],
    session_ids: &[[u8; 32]],
    stakes: &[(ExternalNetworkId, SeraiAddress)],
  ) {
    self.assert_global_db_is_clear();

    for &block_number in block_numbers {
      self.assert_no_substrate_block_hash(block_number);
    }

    for &network in networks {
      self.assert_no_latest_set(network);
    }

    for &set in sets {
      self.assert_no_validators(set);
      self.assert_no_intended_cosigns(set);
    }

    for &session_id in session_ids {
      self.assert_global_sessions_get(session_id, None);
      self.assert_no_global_sessions_last_block(session_id);
    }

    for &(network, validator) in stakes {
      self.assert_no_stakes(network, validator);
    }
  }

  /// Asserts that all global (parameterless) DB entries are cleared.
  /// Use this for a quick check when you don't need to verify parameterized entries.
  fn assert_global_db_is_clear(&self) {
    // create_db! { Cosign {...
    self.assert_no_latest_global_session_intended();

    // create_db!( CosignIntend {...
    self.assert_no_scan_cosign_from();
    self.assert_no_builds_upon();

    // db_channel! { CosignIntendChannels {...
    self.assert_no_global_sessions_channel();
    self.assert_no_block_events();
  }

  fn assert_global_db_is_clear_after_block(&self, block_number: u64) {
    self.assert_global_db_is_clear();

    // create_db! { Cosign {...
    self.assert_no_substrate_block_hash(block_number);
  }

  fn assert_no_global_sessions_last_block(&self, session_id: [u8; 32]) {
    assert_eq!(GlobalSessionsLastBlock::get(&self.db, session_id), None);
  }

  fn assert_task_iteration_per_block_with_notable_events_ran(
    &mut self,
    block_number: u64,
    previous_session_id: Option<[u8; 32]>,
  ) -> ([u8; 32], GlobalSession) {
    let block_hash = self.assert_task_iteration_per_block(block_number);

    // First notable block has no prior session to cosign it, so it's treated as No
    // Subsequent notable blocks have a prior session, so they're treated as Notable
    let expected_has_events =
      if previous_session_id.is_some() { HasEvents::Notable } else { HasEvents::No };
    self.assert_block_events_is_expected(BlockEventData {
      block_number,
      has_events: expected_has_events,
    });

    let mut txn = self.db.txn();
    let channel_entry = GlobalSessionsChannel::try_recv(&mut txn);
    txn.commit();

    let (session_id, session) = channel_entry.unwrap_or_else(|| {
      panic!("GlobalSessionsChannel was empty, expected session for block {block_number}")
    });

    let stored_session = GlobalSessions::get(&self.db, session_id)
      .expect("GlobalSessions should contain the session after notable block");
    Self::assert_global_session(&session, &stored_session);

    assert_eq!(
      session.start_block_number,
      block_number + 1,
      "session should start at block after the notable block"
    );

    assert!(session.total_stake > 0, "session should have non-zero total stake");

    // GlobalSessionsLastBlock is set for the previous session when a new session starts
    if let Some(prev_id) = previous_session_id {
      self.assert_global_sessions_last_block(prev_id, block_number);
    }

    // IntendedCosigns are sent for the previous session's sets
    if let Some(prev_id) = previous_session_id {
      let prev_session =
        GlobalSessions::get(&self.db, prev_id).expect("previous session should exist");
      for set in prev_session.sets {
        self.assert_intended_cosigns_peek(
          set,
          CosignIntent { global_session: prev_id, block_number, block_hash, notable: true },
        );
      }
    }

    (session_id, session)
  }

  fn assert_task_iteration_per_block_with_non_notable_events_ran(&mut self, block_number: u64) {
    let block_hash = self.assert_task_iteration_per_block(block_number);
    self.assert_task_iteration_per_block_concluded(block_number, HasEvents::NonNotable);

    let active_session_id = LatestGlobalSessionIntended::get(&self.db)
      .expect("NonNotable block requires an active session from a prior notable block");

    let session =
      GlobalSessions::get(&self.db, active_session_id).expect("active session should exist");
    for set in session.sets {
      self.assert_intended_cosigns_peek(
        set,
        CosignIntent {
          global_session: active_session_id,
          block_number,
          block_hash,
          notable: false,
        },
      );
    }
  }
}

#[tokio::test]
async fn intend_task_returns_false_with_no_blocks() {
  let test = IntendTest::default();
  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, false).await;
  test.assert_global_db_is_clear();
}

#[tokio::test]
async fn intend_task_returns_false_with_genesis_block() {
  let mut test = IntendTest::default();

  test.serai.make_block(0);

  let mut task = test.into_task();

  // In intend.rs let start_block_number = ScanCosignFrom::get(&self.db).unwrap_or(1);
  // will always default to the 1st block, and without a greater serai.latest_finalized_block_number()
  // there will nothing to iterate, returning false as in "did not progress"
  Test::assert_task_run_iteration_and_check_progress(&mut task, false).await;
  test.assert_global_db_is_clear_after_block(0u64);
}

#[tokio::test]
async fn intend_task_returns_true_with_linear_blocks() {
  let mut test = IntendTest::default();

  test.serai.make_block(1);
  test.serai.make_block(2);
  test.serai.make_block(3);

  let mut task = test.into_task();

  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;
  test.assert_task_iterations_with_no_events_ran(1, 3);
}

#[tokio::test]
async fn intend_task_errors_if_chain_is_not_linear() {
  let mut test = IntendTest::default();

  test.serai.make_block(1);

  // Capture builds_upon after block 1 (before block 2 modifies it)
  let builds_upon_after_block_1 = test.serai.builds_upon.clone();

  // Block #2 does not build upon block #1
  test.serai.builds_upon = IncrementalUnbalancedMerkleTree::new();

  test.serai.make_block(2);

  let mut task = test.into_task();

  Test::assert_task_run_and_failed_with(&mut task, "doesn't build upon").await;

  test.assert_task_iterations_with_no_events_failed_at(2, &builds_upon_after_block_1);

  // Now fix the chain: remove the broken block 2 and recreate it properly
  test.serai.blocks_by_number.remove(&2);
  test.serai.builds_upon = builds_upon_after_block_1;

  test.serai.make_block(2);

  let mut task = test.into_task();

  // Re-run the task, block 2 properly builds upon block 1
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;
  // block 1 was already asserted and cleared from queue, assert only block 2 now
  test.assert_task_iteration_per_block_with_no_events_ran(2);
}

#[tokio::test]
async fn intend_task_errors_if_block_not_found() {
  let mut test = IntendTest::default();

  test.serai.make_block(1);

  // Capture builds_upon after block 1
  let builds_upon_after_block_1 = test.serai.builds_upon.clone();

  // Block 2 exists in terms of finalization, but returns None when fetched
  test.serai.make_block(2);
  test.serai.set_block_not_found(2);

  let mut task = test.into_task();
  Test::assert_task_run_and_failed_with(
    &mut task,
    "couldn't get block which should've been finalized",
  )
  .await;

  test.assert_task_iterations_with_no_events_failed_at(2, &builds_upon_after_block_1);

  test.serai.missing_blocks.remove(&2);

  let mut task = test.into_task();

  // Re-run the task, block 2 now fetched and processed
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;
  test.assert_task_iteration_per_block_with_no_events_ran(2);
}

#[tokio::test]
async fn intend_task_handles_rpc_error_on_block_fetch() {
  let mut test = IntendTest::default();

  test.serai.make_block(1);

  // Capture builds_upon after block 1
  let builds_upon_after_block_1 = test.serai.builds_upon.clone();

  // Block 2 exists in terms of finalization, but fetching it returns an error
  test.serai.make_block(2);
  test.serai.set_block_error(2, "connection refused");

  let mut task = test.into_task();
  Test::assert_task_run_and_failed_with(&mut task, "RPC error fetching block").await;

  test.assert_task_iterations_with_no_events_failed_at(2, &builds_upon_after_block_1);

  test.serai.block_by_number_error.remove(&2);

  let mut task = test.into_task();

  // Re-run the task, block 2 now fetched and processed
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;
  test.assert_task_iteration_per_block_with_no_events_ran(2);
}

#[tokio::test]
async fn intend_task_handles_rpc_error_on_events_fetch() {
  let mut test = IntendTest::default();

  test.serai.make_block(1);

  // Capture builds_upon after block 1
  let builds_upon_after_block_1 = test.serai.builds_upon.clone();

  // Block 2 exists in terms of finalization, but fetching it returns an event error
  let block2_hash = test.serai.make_block(2);
  test.serai.set_events_error(block2_hash, "timeout");

  let mut task = test.into_task();
  Test::assert_task_run_and_failed_with(&mut task, "RPC error fetching events").await;

  test.assert_task_iterations_with_no_events_failed_at(2, &builds_upon_after_block_1);

  test.serai.events_error.remove(&block2_hash);

  let mut task = test.into_task();

  // Re-run the task, block 2 now fetched and processed
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;
  test.assert_task_iteration_per_block_with_no_events_ran(2);
}

#[tokio::test]
async fn intend_task_handles_rpc_error_on_latest_finalized() {
  let mut test = IntendTest::default();

  test.serai.make_block(1);
  test.serai.set_latest_finalized_error("network error");

  let mut task = test.into_task();
  Test::assert_task_run_and_failed_with(&mut task, "RPC error fetching latest finalized").await;

  test.serai.latest_finalized_error = None;

  let mut task = test.into_task();

  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;
  test.assert_task_iteration_per_block_with_no_events_ran(1);
}

#[tokio::test]
async fn intend_task_handles_allocation_events() {
  let mut test = IntendTest::default();

  let validator1 = SeraiAddress([0x01; 32]);
  let validator2 = SeraiAddress([0x02; 32]);

  let allocations_block1 = [
    (validator1, ExternalNetworkId::Bitcoin, 50),
    (validator1, ExternalNetworkId::Bitcoin, 100),
    (validator2, ExternalNetworkId::Bitcoin, 200),
    (validator1, ExternalNetworkId::Ethereum, 150),
  ];
  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(block1_hash, events_from_allocations(&allocations_block1));

  let allocations_block2 =
    [(validator2, ExternalNetworkId::Ethereum, 75), (validator1, ExternalNetworkId::Bitcoin, 25)];

  let block2_hash = test.serai.make_block(2);
  test.serai.set_events(block2_hash, events_from_allocations(&allocations_block2));

  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

  let all_allocations: Vec<_> =
    allocations_block1.iter().chain(allocations_block2.iter()).copied().collect();

  test.assert_stakes_from_allocations_is_expected(&all_allocations);

  // Both blocks have only allocation events which are a HasEvents::No
  // not HasEvents::Notable neither HasEvents::NonNotable
  test.assert_task_iterations_with_no_events_ran(1, 2);
}

#[tokio::test]
#[should_panic(expected = "no prior existing stake")]
async fn intend_task_handles_deallocation_without_prior_allocation() {
  let mut test = IntendTest::default();

  let validator = SeraiAddress([0x01; 32]);

  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(
    block1_hash,
    // Deallocate without any prior allocation should panic
    vec![deallocation_event(validator, NetworkId::External(ExternalNetworkId::Bitcoin), 100)],
  );

  let mut task = test.into_task();
  task.run_iteration().await.unwrap();
}

#[tokio::test]
async fn intend_task_handles_deallocation_event() {
  let mut test = IntendTest::default();

  let validator = SeraiAddress([0x01; 32]);

  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(
    block1_hash,
    vec![
      allocation_event(validator, NetworkId::External(ExternalNetworkId::Bitcoin), 100),
      deallocation_event(validator, NetworkId::External(ExternalNetworkId::Bitcoin), 30),
    ],
  );

  // Create task after all blocks are set up
  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

  test.assert_stakes_is_expected(ExternalNetworkId::Bitcoin, validator, Some(Amount(70)));
  test.assert_task_iteration_per_block_with_no_events_ran(1);
}

#[tokio::test]
async fn intend_task_handles_set_decided_event_with_empty_validators() {
  let mut test = IntendTest::default();

  let set0 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
  let vset0 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(0) };

  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(block1_hash, vec![set_decided_event(vset0, vec![])]);

  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

  // Verify that an empty validators vec results in no validators being stored
  test.assert_validators_is_expected(set0, None);

  // SetDecided is a HasEvents::No type
  test.assert_task_iteration_per_block_with_no_events_ran(1);
}

#[tokio::test]
async fn intend_task_handles_set_decided_event() {
  let mut test = IntendTest::default();

  let validator1 = SeraiAddress([0x01; 32]);
  let validator2 = SeraiAddress([0x02; 32]);
  let validator3 = SeraiAddress([0x03; 32]);

  let set0_btc = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
  let vset0_btc =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(0) };
  let set0_eth = ExternalValidatorSet { network: ExternalNetworkId::Ethereum, session: Session(0) };
  let vset0_eth =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Ethereum), session: Session(0) };

  // Block 1: SetDecided for Bitcoin
  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(
    block1_hash,
    vec![set_decided_event(
      vset0_btc,
      vec![
        (validator1, KeyShares::ONE),
        (validator2, KeyShares::try_from(2).unwrap()),
        (validator3, KeyShares::try_from(3).unwrap()),
      ],
    )],
  );

  // Block 2: SetDecided for Ethereum with different validators
  let block2_hash = test.serai.make_block(2);
  test.serai.set_events(
    block2_hash,
    vec![set_decided_event(
      vset0_eth,
      vec![
        (validator1, KeyShares::try_from(2).unwrap()),
        (validator2, KeyShares::try_from(3).unwrap()),
      ],
    )],
  );

  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

  // Verify validators are stored for each set
  test.assert_validators_is_expected(set0_btc, Some(vec![validator1, validator2, validator3]));
  test.assert_validators_is_expected(set0_eth, Some(vec![validator1, validator2]));

  // SetDecided is a HasEvents::No type, not HasEvents::Notable neither HasEvents::NonNotable
  test.assert_task_iterations_with_no_events_ran(1, 2);
}

#[tokio::test]
async fn intend_task_handles_set_keys_without_set_decided() {
  let mut test = IntendTest::default();

  let set0 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };

  // Block 1: SetKeys without prior SetDecided should error
  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(block1_hash, vec![set_keys_event(set0)]);

  let mut task = test.into_task();
  Test::assert_task_run_and_failed_with(&mut task, "set which wasn't decided set keys").await;

  // No state should be recorded since the operation failed
  test.assert_global_db_is_clear_after_block(1);
}

#[tokio::test]
async fn intend_task_handles_set_keys_event() {
  let mut test = IntendTest::default();

  let validator1 = SeraiAddress([0x01; 32]);
  let validator2 = SeraiAddress([0x02; 32]);

  let set0 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
  let vset0 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(0) };
  let set1 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(1) };
  let vset1 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(1) };

  // Block 1: First SetKeys (creates session 0)
  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(
    block1_hash,
    vec![
      allocation_event(validator1, NetworkId::External(ExternalNetworkId::Bitcoin), 100),
      allocation_event(validator2, NetworkId::External(ExternalNetworkId::Bitcoin), 200),
      set_decided_event(
        vset0,
        vec![(validator1, KeyShares::ONE), (validator2, KeyShares::try_from(2).unwrap())],
      ),
      set_keys_event(set0),
    ],
  );

  // Block 2: Second SetKeys (creates session 1)
  let block2_hash = test.serai.make_block(2);
  test.serai.set_events(
    block2_hash,
    vec![
      set_decided_event(
        vset1,
        vec![(validator1, KeyShares::try_from(2).unwrap()), (validator2, KeyShares::ONE)],
      ),
      set_keys_event(set1),
    ],
  );

  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

  let expected_set = Set { session: Session(1), key: Public([0xff; 32]), stake: Amount(300) };
  test.assert_latest_set_is_expected(ExternalNetworkId::Bitcoin, Some(&expected_set));

  test.assert_validators_is_expected(set0, None);
  test.assert_validators_is_expected(set1, None);

  // Block 1: First notable block (no prior session) -> HasEvents::No
  let (session0_id, _) = test.assert_task_iteration_per_block_with_notable_events_ran(1, None);

  // Block 2: Second notable block (prior session exists) -> HasEvents::Notable
  test.assert_task_iteration_per_block_with_notable_events_ran(2, Some(session0_id));

  test.assert_scan_cosign_from_is_expected(3);
}

#[tokio::test]
async fn intend_task_handles_set_keys_event_error_if_notable_block_has_no_stake() {
  let mut test = IntendTest::default();

  let validator1 = SeraiAddress([0x01; 32]);
  let validator2 = SeraiAddress([0x02; 32]);

  let set0 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
  let vset0 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(0) };
  let set1 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(1) };
  let vset1 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(1) };

  // Block 1: Normal notable block with allocations
  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(
    block1_hash,
    vec![
      allocation_event(validator1, NetworkId::External(ExternalNetworkId::Bitcoin), 100),
      set_decided_event(vset0, vec![(validator1, KeyShares::ONE)]),
      set_keys_event(set0),
    ],
  );

  // Block 2: SetDecided and SetKeys for new session with validator2 who has no allocations -> 0 stake
  let block2_hash = test.serai.make_block(2);
  test.serai.set_events(
    block2_hash,
    vec![set_decided_event(vset1, vec![(validator2, KeyShares::ONE)]), set_keys_event(set1)],
  );

  let mut task = test.into_task();
  Test::assert_task_run_and_failed_with(&mut task, "had 0 stake").await;
}

#[tokio::test]
async fn intend_task_handles_burn_with_instruction_events() {
  let mut test = IntendTest::default();

  let validator1 = SeraiAddress([0x01; 32]);
  let validator2 = SeraiAddress([0x02; 32]);

  let set0 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
  let vset0 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(0) };

  // Block 1: Create a session (first notable block, treated as No because no prior session)
  let allocations_block1 =
    [(validator1, ExternalNetworkId::Bitcoin, 100), (validator2, ExternalNetworkId::Bitcoin, 200)];
  let block1_hash = test.serai.make_block(1);
  let mut events = events_from_allocations(&allocations_block1);
  events.push(set_decided_event(
    vset0,
    vec![(validator1, KeyShares::ONE), (validator2, KeyShares::try_from(2).unwrap())],
  ));
  events.push(set_keys_event(set0));
  test.serai.set_events(block1_hash, events);

  // Block 2: Burn event makes block NonNotable (with additional allocations)
  let allocations_block2 = [(validator1, ExternalNetworkId::Bitcoin, 50)];
  let block2_hash = test.serai.make_block(2);
  let mut events2 = events_from_allocations(&allocations_block2);
  events2.push(burn_with_instruction_event(validator1));
  test.serai.set_events(block2_hash, events2);

  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

  test.assert_stakes_is_expected(ExternalNetworkId::Bitcoin, validator1, Some(Amount(150)));
  test.assert_stakes_is_expected(ExternalNetworkId::Bitcoin, validator2, Some(Amount(200)));

  // Block 1: First notable block (no prior session, treated as No)
  test.assert_task_iteration_per_block(1);
  test
    .assert_block_events_is_expected(BlockEventData { block_number: 1, has_events: HasEvents::No });

  // Block 2: NonNotable (has burn event, session exists from block 1)
  test.assert_task_iteration_per_block_with_non_notable_events_ran(2);
}

#[tokio::test]
async fn intend_task_handles_ignore_non_validator_sets_events() {
  let mut test = IntendTest::default();

  let vset0 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(0) };
  let vset1 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Ethereum), session: Session(0) };

  // Block 1: Signals event (outer _ => continue) and AcceptedHandover (inner _ => continue)
  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(
    block1_hash,
    vec![
      Event::Signals(signals::Event::NetworkHalted { network: ExternalNetworkId::Bitcoin }),
      Event::ValidatorSets(validator_sets::Event::AcceptedHandover { set: vset0 }),
    ],
  );

  // Block 2: More ignored events on different network
  let block2_hash = test.serai.make_block(2);
  test.serai.set_events(
    block2_hash,
    vec![
      Event::Signals(signals::Event::NetworkHalted { network: ExternalNetworkId::Ethereum }),
      Event::ValidatorSets(validator_sets::Event::AcceptedHandover { set: vset1 }),
    ],
  );

  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

  // Both blocks have only ignored events -> HasEvents::No
  test.assert_task_iterations_with_no_events_ran(1, 2);
}

#[tokio::test]
async fn intend_task_handles_ignore_non_burn_with_instruction_coins_events() {
  let mut test = IntendTest::default();

  let validator = SeraiAddress([0x01; 32]);

  // Block 1: Mint and Transfer events (should be ignored)
  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(
    block1_hash,
    vec![
      Event::Coins(coins::Event::Mint {
        to: validator,
        coins: Balance { coin: Coin::External(ExternalCoin::Bitcoin), amount: Amount(100) },
      }),
      Event::Coins(coins::Event::Transfer {
        from: validator,
        to: SeraiAddress([0x02; 32]),
        coins: Balance { coin: Coin::External(ExternalCoin::Bitcoin), amount: Amount(50) },
      }),
    ],
  );

  // Block 2: Burn event (not BurnWithInstruction, should be ignored)
  let block2_hash = test.serai.make_block(2);
  test.serai.set_events(
    block2_hash,
    vec![Event::Coins(coins::Event::Burn {
      from: validator,
      coins: Balance { coin: Coin::External(ExternalCoin::Bitcoin), amount: Amount(50) },
    })],
  );

  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

  // All Coins events except BurnWithInstruction are ignored -> HasEvents::No
  test.assert_task_iterations_with_no_events_ran(1, 2);
}

#[tokio::test]
async fn intend_task_handles_ignores_serai_network_events() {
  let mut test = IntendTest::default();

  let validator = SeraiAddress([0x01; 32]);

  let vset_serai = ValidatorSet { network: NetworkId::Serai, session: Session(0) };

  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(
    block1_hash,
    vec![
      allocation_event(validator, NetworkId::Serai, 100),
      // Can even try a greater deallocation amount, both will be ignored anyway
      deallocation_event(validator, NetworkId::Serai, 150),
    ],
  );

  let block2_hash = test.serai.make_block(2);
  test.serai.set_events(
    block2_hash,
    vec![set_decided_event(vset_serai, vec![(validator, KeyShares::ONE)])],
  );

  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

  test.assert_task_iterations_with_no_events_ran(1, 2);
}

#[tokio::test]
async fn intend_task_handles_downgrades_events_when_no_session_available() {
  let mut test = IntendTest::default();

  let validator1 = SeraiAddress([0x01; 32]);
  let validator2 = SeraiAddress([0x02; 32]);

  let set0 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
  let vset0 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(0) };

  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(block1_hash, vec![burn_with_instruction_event(validator1)]);

  let allocations_block2 =
    [(validator1, ExternalNetworkId::Bitcoin, 100), (validator2, ExternalNetworkId::Bitcoin, 200)];
  let block2_hash = test.serai.make_block(2);
  let mut events = events_from_allocations(&allocations_block2);
  events.push(set_decided_event(
    vset0,
    vec![(validator1, KeyShares::ONE), (validator2, KeyShares::try_from(2).unwrap())],
  ));
  events.push(set_keys_event(set0));
  test.serai.set_events(block2_hash, events);

  let block3_hash = test.serai.make_block(3);
  test.serai.set_events(block3_hash, vec![burn_with_instruction_event(validator2)]);

  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

  test.assert_task_iteration_per_block(1);
  test
    .assert_block_events_is_expected(BlockEventData { block_number: 1, has_events: HasEvents::No });

  test.assert_task_iteration_per_block(2);
  test
    .assert_block_events_is_expected(BlockEventData { block_number: 2, has_events: HasEvents::No });

  test.assert_task_iteration_per_block_with_non_notable_events_ran(3);

  test.assert_scan_cosign_from_is_expected(4);
}

#[tokio::test]
async fn intend_task_handles_errors_when_global_session_not_in_database() {
  use serai_db::Db as _;

  let mut test = IntendTest::default();

  let validator = SeraiAddress([0x01; 32]);

  let fake_session_id = [0xAB; 32];
  {
    let mut txn = test.db.txn();
    LatestGlobalSessionIntended::set(&mut txn, &fake_session_id);
    txn.commit();
  }

  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(block1_hash, vec![burn_with_instruction_event(validator)]);

  let mut task = test.into_task();
  Test::assert_task_run_and_failed_with(&mut task, "wasn't saved to the database").await;

  test.assert_no_substrate_block_hash(1);
  test.assert_no_scan_cosign_from();
  test.assert_no_block_events();

  test.assert_latest_global_session_intended(Some(fake_session_id));
}

#[tokio::test]
async fn intend_task_handles_safeguard_prevents_cosigning_with_no_session() {
  let mut test = IntendTest::default();

  let validator1 = SeraiAddress([0x01; 32]);
  let validator2 = SeraiAddress([0x02; 32]);

  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(block1_hash, vec![burn_with_instruction_event(validator1)]);

  let set0 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
  let vset0 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(0) };

  let allocations =
    [(validator1, ExternalNetworkId::Bitcoin, 100), (validator2, ExternalNetworkId::Bitcoin, 200)];
  let block2_hash = test.serai.make_block(2);
  let mut events = events_from_allocations(&allocations);
  events.push(set_decided_event(vset0, vec![(validator1, KeyShares::ONE)]));
  events.push(set_keys_event(set0));
  test.serai.set_events(block2_hash, events);

  let mut task = test.into_task();
  Test::assert_task_run_iteration_and_check_progress(&mut task, true).await;

  test.assert_task_iteration_per_block(1);
  test
    .assert_block_events_is_expected(BlockEventData { block_number: 1, has_events: HasEvents::No });

  test.assert_task_iteration_per_block(2);
  test
    .assert_block_events_is_expected(BlockEventData { block_number: 2, has_events: HasEvents::No });

  assert!(
    LatestGlobalSessionIntended::get(&test.db).is_some(),
    "session should have been created by block 2"
  );

  test.assert_scan_cosign_from_is_expected(3);
}
