use std::{collections::HashMap, sync::Arc};

use rand_core::{OsRng, RngCore};

use serai_db::MemDb;

use serai_shim_rpc::SeraiShimRpc;

use serai_client_serai::{
  Serai,
  abi::{
    Event, coins,
    primitives::{
      address::{ExternalAddress, SeraiAddress},
      balance::{Amount, ExternalBalance},
      coin::ExternalCoin,
      crypto::{ExternalKey, KeyPair, Public},
      instructions::{OutInstruction, OutInstructionWithBalance},
      network_id::{ExternalNetworkId, NetworkId},
      validator_sets::{ExternalValidatorSet, KeyShares, Session, ValidatorSet},
    },
    validator_sets,
  },
};

use crate::{intend::*, tests::*, *};

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

  let num_blocks_u64 = u64::try_from(num_blocks).unwrap();

  // ScanCosignFrom should point to the block after the last processed
  assert_eq!(
    ScanCosignFrom::get(db),
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
    assert_eq!(
      db_stake,
      Some(Amount(expected_amount)),
      "stake mismatch for ({network:?}, {validator:?}): db={db_stake:?}, expected={expected_amount}"
    );
  }

  // Verify LatestSet matches the expected.
  for (&network, &(session, stake)) in &expected_latest_set {
    let latest = LatestSet::get(db, network);
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
      assert_eq!(
        Validators::get(db, last_set),
        None,
        "Validators for {last_set:?} should have been consumed by SetKeys"
      );
    }
  }

  // If any SetKeys happened, a GlobalSession should exist with consistent total_stake
  if set_keys_count > 0 {
    let session_id = LatestGlobalSessionIntended::get(db);
    assert!(
      session_id.is_some(),
      "LatestGlobalSessionIntended should exist after {set_keys_count} SetKeys events",
    );
    let session = GlobalSessions::get(db, session_id.unwrap());
    assert!(session.is_some(), "GlobalSession should exist");
    let session = session.unwrap();
    let sum: u64 = session.stakes.values().sum();
    assert_eq!(
      session.total_stake, sum,
      "GlobalSession total_stake should equal sum of individual stakes"
    );
  }

  serai_log::log::info!(
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
    let (serai, task_test) = setup_mock_test().await;

    serai.make_block(0, vec![]).await;
    serai.make_block(1, vec![]).await;
    serai.set_error("blockchain/latest_finalized_block_number", "network error").await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching latest finalized").await;

    // No blocks processed — error happened before scanning
    assert_eq!(ScanCosignFrom::get(&task_test.db), None);

    serai.clear_error("blockchain/latest_finalized_block_number").await;

    let mut task = task_test.into_task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    verify_db_invariants(&task_test.db, &task_test.serai, 2).await;
  }
}

/// Random event, state, and block generator.
struct EventFuzzer {
  /// Monotonic counter hashed with blake2 for deterministic pseudo-random bytes.
  counter: u64,
  /// Seed bytes.
  seed: [u8; 32],
  /// Available validator addresses.
  validators: Vec<SeraiAddress>,
  /// All networks.
  networks: Vec<NetworkId>,
  /// Running stake ledger: `(network, validator) -> accumulated_stake`.
  stakes: HashMap<(ExternalNetworkId, SeraiAddress), u64>,
  /// Sets that have been decided but not yet keyed.
  pending_keys: HashMap<ExternalValidatorSet, Vec<SeraiAddress>>,
  /// Next session number per network.
  next_session: HashMap<ExternalNetworkId, u32>,
}

impl EventFuzzer {
  fn new() -> Self {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);

    let num_validators = usize::try_from((OsRng.next_u64() % 17) + 4).unwrap();

    let validators: Vec<SeraiAddress> = (0 .. num_validators)
      .map(|i| {
        let mut bytes = [0u8; 32];
        bytes[0 .. 8].copy_from_slice(&u64::try_from(i).unwrap().to_le_bytes());
        bytes[8 .. 16].copy_from_slice(&seed[0 .. 8]);
        SeraiAddress(bytes)
      })
      .collect();

    let networks: Vec<NetworkId> = NetworkId::all().collect();

    Self {
      counter: 0,
      seed,
      validators,
      networks,
      stakes: HashMap::new(),
      pending_keys: HashMap::new(),
      next_session: HashMap::new(),
    }
  }

  /// Generate a pseudo-random `u64` by hashing counter + seed with blake2.
  fn next_u64(&mut self) -> u64 {
    use blake2::{Blake2b256, Digest as _};
    let hash =
      Blake2b256::new().chain_update(self.seed).chain_update(self.counter.to_le_bytes()).finalize();
    self.counter += 1;
    u64::from_le_bytes(hash[0 .. 8].try_into().unwrap())
  }

  /// Pick a random element from a slice.
  fn pick<'a, T>(&mut self, slice: &'a [T]) -> &'a T {
    let idx = self.next_u64() % u64::try_from(slice.len()).unwrap();
    &slice[usize::try_from(idx).unwrap()]
  }

  /// Generate a random allocation event.
  fn random_allocation(&mut self) -> Event {
    let validator = *self.pick(&self.validators.clone());
    let network = *self.pick(&self.networks.clone());
    let amount = (self.next_u64() % 10000) + 1; // 1..=10000
    if let Ok(ext) = ExternalNetworkId::try_from(network) {
      *self.stakes.entry((ext, validator)).or_default() += amount;
    }
    allocation_event(validator, network, amount)
  }

  /// Generate a random deallocation event. Returns `None` if no validator has stake.
  fn random_deallocation(&mut self) -> Option<Event> {
    // ~25% chance of generating a Serai deallocation (exercises the `continue` branch)
    if self.next_u64() % 4 == 0 {
      let validator = *self.pick(&self.validators.clone());
      let amount = (self.next_u64() % 100) + 1;
      return Some(deallocation_event(validator, NetworkId::Serai, amount));
    }

    let candidates: Vec<((ExternalNetworkId, SeraiAddress), u64)> =
      self.stakes.iter().filter(|(_, &s)| s > 0).map(|(&k, &v)| (k, v)).collect();
    if candidates.is_empty() {
      return None;
    }
    let idx = self.next_u64() % u64::try_from(candidates.len()).unwrap();
    let ((network, validator), current_stake) = candidates[usize::try_from(idx).unwrap()];
    let amount = (self.next_u64() % current_stake) + 1; // 1..=current_stake
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
    let count = usize::try_from((self.next_u64() % u64::try_from(max_count).unwrap()) + 1).unwrap();

    // Shuffle-pick by swapping from a clone
    let mut pool = self.validators.clone();
    let mut chosen = Vec::with_capacity(count);
    for _ in 0 .. count {
      let idx = usize::try_from(self.next_u64() % u64::try_from(pool.len()).unwrap()).unwrap();
      chosen.push(pool.swap_remove(idx));
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
    let idx = usize::try_from(self.next_u64() % u64::try_from(keys.len()).unwrap()).unwrap();
    let set = keys[idx];
    // Remove from pending — the task will Validators::take it
    self.pending_keys.remove(&set);

    // Advance session for this network so the next SetDecided gets session+1
    *self.next_session.entry(set.network).or_insert(0) += 1;

    let mut public = Public([0u8; 32]);
    public.0[0 .. 8].copy_from_slice(&self.next_u64().to_le_bytes());
    let external_key = ExternalKey(vec![1u8].try_into().unwrap());
    let key_pair = KeyPair(public, external_key);

    Some(Event::ValidatorSets(validator_sets::Event::SetKeys { set, key_pair }))
  }

  /// Generate a random BurnWithInstruction event.
  fn random_burn(&mut self) -> Event {
    let mut burn_address = SeraiAddress([0u8; 32]);
    burn_address.0[0 .. 8].copy_from_slice(&self.next_u64().to_le_bytes());
    burn_with_instruction_event(burn_address)
  }

  /// Generate random events for a single block.
  fn generate_block_events(&mut self) -> Vec<Vec<Event>> {
    let num_events = self.next_u64() % 8; // 0..=7 events per block
    if num_events == 0 {
      return vec![];
    }

    let mut alloc_count = 0u64;
    let mut dealloc_count = 0u64;
    let mut set_decided_count = 0u64;
    let mut set_keys_count = 0u64;
    let mut burn_count = 0u64;

    for _ in 0 .. num_events {
      match self.next_u64() % 100 {
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
      let j = usize::try_from(self.next_u64() % u64::try_from(i + 1).unwrap()).unwrap();
      events.swap(i, j);
    }

    if events.is_empty() {
      vec![]
    } else {
      vec![events]
    }
  }

  /// Generate multiple blocks of random events.
  fn generate_blocks(&mut self, count: usize) -> Vec<Vec<Vec<Event>>> {
    let mut blocks = Vec::with_capacity(count);
    for _ in 0 .. count {
      blocks.push(self.generate_block_events());
    }
    blocks
  }
}

#[tokio::test]
async fn fuzzed_event_processing() {
  let _ = env_logger::try_init();

  let num_blocks = 1000;

  let mut fuzzer = EventFuzzer::new();
  let blocks = fuzzer.generate_blocks(num_blocks);

  serai_log::log::info!(
    "Fuzz test: {} blocks, {} validators, seed={:?}",
    num_blocks,
    fuzzer.validators.len(),
    hex::encode(fuzzer.seed)
  );

  let (serai, task_test) = setup_mock_test().await;
  for (i, events) in blocks.into_iter().enumerate() {
    serai.make_block(u64::try_from(i).unwrap(), events).await;
  }

  let mut task = task_test.into_task();
  TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

  verify_db_invariants(&task_test.db, &task_test.serai, num_blocks).await;
}
