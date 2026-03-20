use std::{collections::HashMap, sync::Arc};

use rand_core::{OsRng, RngCore};

use serai_db::MemDb;

use serai_shim_rpc::SeraiShimRpc;

use serai_client_serai::{
  Serai,
  abi::{
    Event, coins,
    primitives::{
      address::SeraiAddress,
      balance::{Amount, ExternalBalance},
      coin::ExternalCoin,
      crypto::KeyPair,
      instructions::{OutInstruction, OutInstructionWithBalance},
      network_id::{ExternalNetworkId, NetworkId},
      validator_sets::{ExternalValidatorSet, KeyShares, Session, ValidatorSet},
    },
    validator_sets,
  },
};
use serai_primitives::test_helpers::{
  random_external_address, random_external_key, random_keypair, random_serai_address,
};

use crate::{intend::*, tests::*, *};

pub(super) fn set_decided_event(
  set: ValidatorSet,
  validators: Vec<(SeraiAddress, KeyShares)>,
) -> Event {
  Event::ValidatorSets(validator_sets::Event::SetDecided { set, validators })
}

pub(super) fn allocation_event(validator: SeraiAddress, network: NetworkId, amount: u64) -> Event {
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
    timeline: serai_abi::primitives::validator_sets::DeallocationTimeline::Immediate,
  })
}

pub(super) fn burn_with_instruction_event(from: SeraiAddress) -> Event {
  Event::Coins(coins::Event::BurnWithInstruction {
    from,
    instruction: OutInstructionWithBalance {
      instruction: OutInstruction::Transfer(random_external_address(&mut OsRng)),
      balance: ExternalBalance { coin: ExternalCoin::Bitcoin, amount: Amount(1) },
    },
  })
}

pub(crate) struct IntendTestStruct {
  pub(crate) serai: Arc<Serai>,
  pub(crate) db: MemDb,
}

impl IntoTask for IntendTestStruct {
  type Task = CosignIntendTask<MemDb>;

  fn into_task(&self) -> Self::Task {
    CosignIntendTask { db: self.db.clone(), serai: self.serai.clone() }
  }
}

/// Create a [`SeraiShimRpc`] and a [`IntendTestStruct`] connected to it.
async fn setup_mock_test() -> (SeraiShimRpc, IntendTestStruct) {
  let (shim_serai, serai) = setup_shim_serai().await;
  (shim_serai, IntendTestStruct { serai, db: MemDb::new() })
}

/// Verify all post-run DB invariants by replaying events from the Serai node.
async fn verify_db_invariants(db: &MemDb, serai: &Serai, num_blocks: usize) {
  use serai_client_serai::abi::validator_sets::Event as VsEvent;
  use serai_env::log::debug;

  let num_blocks_u64 = u64::try_from(num_blocks).unwrap();

  // ScanCosignFrom should point to the block after the last processed
  let scan_from = ScanCosignFrom::get(db);
  debug!("ScanCosignFrom: {scan_from:?}");
  assert_eq!(
    scan_from,
    Some(num_blocks_u64),
    "ScanCosignFrom should be {num_blocks} after processing blocks 0..={n}",
    n = num_blocks - 1
  );

  // Replay events from the shim node to compute expected DB state.
  let mut expected_stakes: HashMap<(ExternalNetworkId, SeraiAddress), u64> = HashMap::new();
  let mut expected_latest_set: HashMap<ExternalNetworkId, (Session, u64)> = HashMap::new();
  let mut decided_validators: HashMap<ExternalValidatorSet, Vec<SeraiAddress>> = HashMap::new();
  let mut next_session: HashMap<ExternalNetworkId, u32> = HashMap::new();
  let mut set_keys_count = 0usize;

  for block_num in 0 .. num_blocks_u64 {
    let block = serai.block_by_number(block_num).await.unwrap().unwrap();
    let hash = block.header.hash();
    let events = serai.events(hash).await.unwrap();
    let vset = events.validator_sets();

    for event in vset.allocation_events() {
      let VsEvent::Allocation { validator, network, amount } = event else { continue };
      let Ok(net) = ExternalNetworkId::try_from(*network) else { continue };
      *expected_stakes.entry((net, *validator)).or_default() += amount.0;
    }
    for event in vset.deallocation_events() {
      let VsEvent::Deallocation { validator, network, amount, .. } = event else { continue };
      let Ok(net) = ExternalNetworkId::try_from(*network) else { continue };
      *expected_stakes.entry((net, *validator)).or_default() -= amount.0;
    }
    for event in vset.set_decided_events() {
      let VsEvent::SetDecided { set, validators } = event else { continue };
      let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };
      decided_validators.insert(set, validators.iter().map(|(v, _)| *v).collect());
    }
    for event in vset.set_keys_events() {
      let VsEvent::SetKeys { set, .. } = event else { continue };
      let validators = decided_validators.get(set).cloned().unwrap_or_default();
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
    debug!("Stakes[{network:?}, {validator:?}]: db={db_stake:?}, expected={expected_amount}");
    assert_eq!(
      db_stake,
      Some(Amount(expected_amount)),
      "stake mismatch for ({network:?}, {validator:?}): db={db_stake:?}, expected={expected_amount}"
    );
  }

  // Verify LatestSet matches the expected.
  for (&network, &(session, stake)) in &expected_latest_set {
    let latest = LatestSet::get(db, network);
    debug!("LatestSet[{network:?}]: db={latest:?}, expected=(session={session:?}, stake={stake})");
    assert!(latest.is_some(), "LatestSet should exist for {network:?}");
    let latest = latest.unwrap();
    assert_eq!(latest.session, session, "LatestSet session mismatch for {network:?}");
    assert_eq!(latest.stake.0, stake, "LatestSet stake mismatch for {network:?}");
  }

  // No pending Validators entries (all should have been taken by SetKeys).
  for (&network, _) in &expected_latest_set {
    let session_num = next_session.get(&network).copied().unwrap_or(0);
    if session_num > 0 {
      let last_set = ExternalValidatorSet { network, session: Session(session_num - 1) };
      let validators = Validators::get(db, last_set);
      debug!("Validators[{last_set:?}]: {validators:?} (should be None)");
      assert_eq!(
        validators, None,
        "Validators for {last_set:?} should have been consumed by SetKeys"
      );
    }
  }

  // Log and verify LatestGlobalSessionIntended
  let latest_session_id = LatestGlobalSessionIntended::get(db);
  debug!("LatestGlobalSessionIntended: {:?}", latest_session_id.map(hex::encode));

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

    debug!(
      "GlobalSession {}: start_block_number={}, total_stake={}, sets={:?}, stakes={:?}",
      &hex::encode(session_id)[.. 16],
      session.start_block_number,
      session.total_stake,
      session.sets,
      session.stakes,
    );
    debug!("last_block: {:?}", GlobalSessionsLastBlock::get(db, session_id));

    let sum: u64 = session.stakes.values().sum();
    assert_eq!(
      session.total_stake, sum,
      "GlobalSession total_stake should equal sum of individual stakes"
    );
  }

  // SubstrateBlockHash index
  let max_block = scan_from.unwrap_or(0);
  if max_block > 0 {
    debug!("SubstrateBlockHash index ({max_block} blocks):");
    for b in 0 .. max_block {
      if let Some(hash) = SubstrateBlockHash::get(db, b) {
        debug!("  #{b}: {}…", &hex::encode(hash.0)[.. 16]);
      }
    }
  }

  debug!(
    "DB invariants verified: {} blocks, {} stake entries, {} LatestSets, {} SetKeys events",
    num_blocks,
    expected_stakes.len(),
    expected_latest_set.len(),
    set_keys_count
  );
}

mod errors {
  use super::*;

  #[tokio::test]
  async fn errors_if_chain_is_not_linear() {
    serai_env::init_logger();
    let (serai, task_test) = setup_mock_test().await;

    serai.make_block(0, vec![]).await;
    serai.make_block(1, vec![]).await;
    serai.make_non_linear_block(2, vec![]).await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_and_fails_with(&mut task, "doesn't build upon").await;

    // Blocks 0,1 committed before the error on block 2
    assert_eq!(ScanCosignFrom::get(&task_test.db), Some(2));

    // Fix the chain and re-run
    serai.remove_block(2).await;
    serai.make_block(2, vec![]).await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&task_test.db, &task_test.serai, 3).await;
  }

  #[tokio::test]
  async fn errors_if_block_not_found() {
    serai_env::init_logger();
    let (serai, task_test) = setup_mock_test().await;

    serai.make_block(0, vec![]).await;
    serai.make_block(1, vec![]).await;
    serai.make_block(2, vec![]).await;
    serai.set_block_missing(2).await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_and_fails_with(
      &mut task,
      "couldn't get block which should've been finalized",
    )
    .await;

    assert_eq!(ScanCosignFrom::get(&task_test.db), Some(2));

    serai.clear_block_missing(2).await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&task_test.db, &task_test.serai, 3).await;
  }

  #[tokio::test]
  async fn handles_rpc_error_on_block_fetch() {
    serai_env::init_logger();
    let (serai, task_test) = setup_mock_test().await;

    serai.make_block(0, vec![]).await;
    serai.make_block(1, vec![]).await;
    serai.make_block(2, vec![]).await;
    serai.set_block_number_error("blockchain/block", 2, "connection refused").await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching block").await;

    assert_eq!(ScanCosignFrom::get(&task_test.db), Some(2));

    serai.clear_block_number_error("blockchain/block", 2).await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&task_test.db, &task_test.serai, 3).await;
  }

  #[tokio::test]
  async fn handles_rpc_error_on_events_fetch() {
    serai_env::init_logger();
    let (serai, task_test) = setup_mock_test().await;

    serai.make_block(0, vec![]).await;
    serai.make_block(1, vec![]).await;
    let block2_hash = serai.make_block(2, vec![]).await;
    serai.set_block_hash_error("blockchain/events", block2_hash, "timeout").await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching events").await;

    assert_eq!(ScanCosignFrom::get(&task_test.db), Some(2));

    serai.clear_block_hash_error("blockchain/events", block2_hash).await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&task_test.db, &task_test.serai, 3).await;
  }

  #[tokio::test]
  async fn errors_if_set_decided_has_empty_validators() {
    serai_env::init_logger();
    let (serai, task_test) = setup_mock_test().await;

    serai.make_block(0, vec![]).await;

    let empty_set_decided = set_decided_event(
      ValidatorSet {
        network: NetworkId::External(ExternalNetworkId::Bitcoin),
        session: Session(0),
      },
      vec![],
    );
    serai.make_block(1, vec![vec![empty_set_decided]]).await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_and_fails_with(&mut task, "validator set from Event::SetDecided was empty")
      .await;

    // Block 0 committed, block 1 failed mid-processing
    assert_eq!(ScanCosignFrom::get(&task_test.db), Some(1));
  }

  #[tokio::test]
  async fn handles_rpc_error_on_latest_finalized() {
    serai_env::init_logger();
    let (serai, task_test) = setup_mock_test().await;

    serai.make_block(0, vec![]).await;
    serai.make_block(1, vec![]).await;
    serai.set_error("blockchain/latest_finalized_block_number", "network error").await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching latest finalized").await;

    // No blocks processed, error happened before scanning
    assert_eq!(ScanCosignFrom::get(&task_test.db), None);

    serai.clear_error("blockchain/latest_finalized_block_number").await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&task_test.db, &task_test.serai, 2).await;
  }
}

/// Random event, state, and block generator.
pub(super) struct EventFuzzer {
  /// Available validator addresses.
  pub(super) validators: Vec<SeraiAddress>,
  /// All networks.
  networks: Vec<NetworkId>,
  /// Running stake ledger: `(network, validator) -> accumulated_stake`.
  stakes: HashMap<(ExternalNetworkId, SeraiAddress), u64>,
  /// Sets that have been decided but not yet keyed.
  pending_keys: HashMap<ExternalValidatorSet, Vec<SeraiAddress>>,
  /// Next session number per network.
  pub(super) next_session: HashMap<ExternalNetworkId, u32>,
  /// Keypairs indexed by public key bytes, for signing cosigns.
  pub(super) keypairs: HashMap<[u8; 32], schnorrkel::Keypair>,
}

impl EventFuzzer {
  pub(super) fn new() -> Self {
    // OsRng.next_u64() % 17 = 0..16
    // _ + 4 = 4..20 validators per test
    let num_validators = usize::try_from((OsRng.next_u64() % 17) + 4).unwrap();

    let validators: Vec<SeraiAddress> =
      (0 .. num_validators).map(|_| random_serai_address(&mut OsRng)).collect();

    let networks: Vec<NetworkId> = NetworkId::all().collect();

    Self {
      validators,
      networks,
      stakes: HashMap::new(),
      pending_keys: HashMap::new(),
      next_session: HashMap::new(),
      keypairs: HashMap::new(),
    }
  }

  /// Pick a random element from a slice.
  fn pick<'a, T>(&mut self, slice: &'a [T]) -> &'a T {
    let i = OsRng.next_u64() % u64::try_from(slice.len()).unwrap();
    &slice[usize::try_from(i).unwrap()]
  }

  /// Generate a random amount using a weighted distribution
  fn random_amount(&mut self) -> u64 {
    match OsRng.next_u64() % 20 {
      0 ..= 4 => (OsRng.next_u64() % 10) + 1,
      5 ..= 11 => (OsRng.next_u64() % 990) + 11,
      12 ..= 16 => (OsRng.next_u64() % 99_000) + 1_001,
      _ => (OsRng.next_u64() % 9_900_000) + 100_001,
    }
  }

  /// Generate a random allocation event.
  fn random_allocation(&mut self) -> Event {
    let validator = *self.pick(&self.validators.clone());
    let network = *self.pick(&self.networks.clone());
    let amount = self.random_amount();
    if let Ok(ext) = ExternalNetworkId::try_from(network) {
      *self.stakes.entry((ext, validator)).or_default() += amount;
    }
    allocation_event(validator, network, amount)
  }

  /// Generate a random deallocation event. Returns `None` if no validator has stake.
  fn random_deallocation(&mut self) -> Option<Event> {
    // ~25% chance of generating a Serai deallocation
    if OsRng.next_u64() % 4 == 0 {
      let validator = *self.pick(&self.validators.clone());
      let amount = self.random_amount();
      return Some(deallocation_event(validator, NetworkId::Serai, amount));
    }

    let candidates: Vec<((ExternalNetworkId, SeraiAddress), u64)> =
      self.stakes.iter().filter(|(_, &s)| s > 0).map(|(&k, &v)| (k, v)).collect();
    if candidates.is_empty() {
      return None;
    }
    let i = OsRng.next_u64() % u64::try_from(candidates.len()).unwrap();
    let ((network, validator), current_stake) = candidates[usize::try_from(i).unwrap()];
    // Use weighted amount, clamped to current_stake so we don't underflow
    let amount = self.random_amount().min(current_stake).max(1);
    *self.stakes.entry((network, validator)).or_default() -= amount;
    Some(deallocation_event(validator, NetworkId::External(network), amount))
  }

  /// Generate a random SetDecided event.
  ///
  /// SetDecided only applies to external networks (Serai sessions are managed by the runtime).
  fn random_set_decided(&mut self) -> Option<Event> {
    let external_networks: Vec<ExternalNetworkId> =
      self.networks.iter().copied().filter_map(|n| ExternalNetworkId::try_from(n).ok()).collect();
    let network = *self.pick(&external_networks);
    let session_num = *self.next_session.entry(network).or_insert(0);
    let set = ExternalValidatorSet { network, session: Session(session_num) };

    // Don't double-decide a set that's already pending keys
    if self.pending_keys.contains_key(&set) {
      return None;
    }

    // Pick 1..=min(3, validators.len()) random validators for this set
    let max_count = self.validators.len().min(3);
    let count =
      usize::try_from((OsRng.next_u64() % u64::try_from(max_count).unwrap()) + 1).unwrap();

    // Shuffle-pick by swapping from a clone
    let mut pool = self.validators.clone();
    let mut chosen = Vec::with_capacity(count);
    for _ in 0 .. count {
      let i = usize::try_from(OsRng.next_u64() % u64::try_from(pool.len()).unwrap()).unwrap();
      chosen.push(pool.swap_remove(i));
    }

    self.pending_keys.insert(set, chosen.clone());

    let validators_with_shares: Vec<(SeraiAddress, KeyShares)> =
      chosen.into_iter().map(|v| (v, KeyShares::ONE)).collect();

    Some(set_decided_event(
      ValidatorSet { network: NetworkId::External(network), session: Session(session_num) },
      validators_with_shares,
    ))
  }

  /// Generate a random SetKeys event for a pending (decided but not yet keyed) set.
  fn random_set_keys(&mut self) -> Option<Event> {
    if self.pending_keys.is_empty() {
      return None;
    }

    let keys: Vec<ExternalValidatorSet> = self.pending_keys.keys().copied().collect();
    let i = usize::try_from(OsRng.next_u64() % u64::try_from(keys.len()).unwrap()).unwrap();
    let set = keys[i];
    // Remove from pending - the task will Validators::take it
    self.pending_keys.remove(&set);

    // Advance session for this network so the next SetDecided gets session+1
    *self.next_session.entry(set.network).or_insert(0) += 1;

    let (keypair, public) = random_keypair(&mut OsRng);
    self.keypairs.insert(public.0, keypair);
    let external_key = random_external_key(&mut OsRng);
    let key_pair = KeyPair(public, external_key);

    Some(Event::ValidatorSets(validator_sets::Event::SetKeys { set, key_pair }))
  }

  /// Generate a random BurnWithInstruction event.
  fn random_burn(&mut self) -> Event {
    let mut burn_address = SeraiAddress([0u8; 32]);
    burn_address.0[0 .. 8].copy_from_slice(&OsRng.next_u64().to_le_bytes());
    burn_with_instruction_event(burn_address)
  }

  /// Generate random events for a single block.
  fn generate_block_events(&mut self) -> Vec<Vec<Event>> {
    let num_events = OsRng.next_u64() % 8; // 0..=7 events per block
    if num_events == 0 {
      return vec![];
    }

    let mut alloc_count = 0u64;
    let mut dealloc_count = 0u64;
    let mut set_decided_count = 0u64;
    let mut set_keys_count = 0u64;
    let mut burn_count = 0u64;

    for _ in 0 .. num_events {
      match OsRng.next_u64() % 100 {
        0 ..= 35 => alloc_count += 1,
        36 ..= 55 => dealloc_count += 1,
        56 ..= 70 => set_decided_count += 1,
        71 ..= 85 => set_keys_count += 1,
        86 ..= 99 => burn_count += 1,
        _ => unreachable!(),
      }
    }

    let mut events = Vec::new();

    // Update the stakes
    for _ in 0 .. alloc_count {
      events.push(self.random_allocation());
    }
    for _ in 0 .. dealloc_count {
      if let Some(e) = self.random_deallocation() {
        events.push(e);
      }
    }

    // Handle decided sets
    for _ in 0 .. set_decided_count {
      if let Some(e) = self.random_set_decided() {
        events.push(e);
      }
    }

    // Handle declarations of the latest set
    for _ in 0 .. set_keys_count {
      if let Some(event) = self.random_set_keys() {
        events.push(event);
      }
    }

    // Handle burn with instruction events (makes block non-notable if not already notable)
    for _ in 0 .. burn_count {
      events.push(self.random_burn());
    }

    // Shuffle the events to test order-independence
    for i in (1 .. events.len()).rev() {
      let j = usize::try_from(OsRng.next_u64() % u64::try_from(i + 1).unwrap()).unwrap();
      events.swap(i, j);
    }

    if events.is_empty() {
      vec![]
    } else {
      vec![events]
    }
  }

  /// Generate multiple blocks of random events.
  pub(super) fn generate_blocks(&mut self, count: usize) -> Vec<Vec<Vec<Event>>> {
    let mut blocks = Vec::with_capacity(count);
    for _ in 0 .. count {
      blocks.push(self.generate_block_events());
    }
    blocks
  }
}

#[tokio::test]
async fn deallocating_zero_is_a_noop() {
  serai_env::init_logger();
  let (serai, task_test) = setup_mock_test().await;

  let validator = random_serai_address(&mut OsRng);
  let network = NetworkId::External(ExternalNetworkId::Bitcoin);

  {
    // Block 0: allocate 0 stake to the validator
    serai.make_block(0, vec![vec![allocation_event(validator, network, 0)]]).await;
    // Block 1: deallocate 0 from the same validator
    serai.make_block(1, vec![vec![deallocation_event(validator, network, 0)]]).await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    // Verify it works and the stake is unchanged after the 0-deallocation
    let stake = Stakes::get(&task_test.db, ExternalNetworkId::Bitcoin, validator);
    assert_eq!(stake, Some(Amount(0)), "stake should be unchanged after deallocating 0");
  }

  {
    let amount = OsRng.next_u64();
    // Block 2: allocate stake to the validator
    serai.make_block(2, vec![vec![allocation_event(validator, network, amount)]]).await;
    // Block 3: deallocate 0 from the same validator
    serai.make_block(3, vec![vec![deallocation_event(validator, network, 0)]]).await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    // Verify the 0-deallocation works and the stake is unchanged after it
    let stake = Stakes::get(&task_test.db, ExternalNetworkId::Bitcoin, validator);
    assert_eq!(stake, Some(Amount(amount)), "stake should be unchanged after deallocating 0");
  }
}

#[tokio::test]
async fn fuzzed_event_processing() {
  serai_env::init_logger();

  let num_blocks = 1000;

  let mut fuzzer = EventFuzzer::new();
  let blocks = fuzzer.generate_blocks(num_blocks);

  serai_env::log::info!("Fuzz test: {} blocks, {} validators", num_blocks, fuzzer.validators.len(),);

  let (serai, task_test) = setup_mock_test().await;
  for (i, events) in blocks.into_iter().enumerate() {
    serai.make_block(u64::try_from(i).unwrap(), events).await;
  }

  let mut task = task_test.into_task();
  TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

  verify_db_invariants(&task_test.db, &task_test.serai, num_blocks).await;
}
