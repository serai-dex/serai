use core::future::Future;
use std::collections::HashMap;

use serai_db::{Db as _, DbTxn};

use serai_client_serai::{
  abi::{
    primitives::{
      address::{SeraiAddress, ExternalAddress},
      balance::{Amount, ExternalBalance},
      coin::ExternalCoin,
      crypto::{Public, ExternalKey, KeyPair},
      instructions::{OutInstruction, OutInstructionWithBalance},
      network_id::{ExternalNetworkId, NetworkId},
      validator_sets::{Session, ValidatorSet, ExternalValidatorSet, KeyShares},
      BlockHash,
    },
    coins, system, validator_sets, Block, Event,
  },
  Events,
};

use crate::{
  intend::{
    BlockEventData, BlockEvents, BuildsUpon, CosignIntendTask, GlobalSessionsChannel,
    IntendedCosigns, LatestSet, ScanCosignFrom, Set, Stakes, Validators,
  },
  tests::*,
  CosignIntent, GlobalSession, GlobalSessions, GlobalSessionsLastBlock, HasEvents,
  LatestGlobalSessionIntended, SeraiRpc, SubstrateBlockHash,
};

fn set_keys_event_with_pair(set: ExternalValidatorSet, key_pair: &KeyPair) -> Event {
  Event::ValidatorSets(validator_sets::Event::SetKeys { set, key_pair: key_pair.clone() })
}

fn set_keys_event(set: ExternalValidatorSet, key_seed: u8) -> Event {
  let key_pair =
    KeyPair(Public([key_seed; 32]), ExternalKey(vec![key_seed; 32].try_into().unwrap()));
  set_keys_event_with_pair(set, &key_pair)
}

fn set_decided_event(set: ValidatorSet, validator: SeraiAddress) -> Event {
  Event::ValidatorSets(validator_sets::Event::SetDecided {
    set,
    validators: vec![(validator, KeyShares(1))],
  })
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
  let address = ExternalAddress::try_from(vec![1u8, 2u8, 3u8]).unwrap();
  Event::Coins(coins::Event::BurnWithInstruction {
    from,
    instruction: OutInstructionWithBalance {
      instruction: OutInstruction::Transfer(address),
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

impl Test {
  fn assert_substrate_block_hash_exists(&self, block_number: u64) -> BlockHash {
    let block_hash = SubstrateBlockHash::get(&self.db, block_number);
    assert!(block_hash.is_some(), "no substrate blockhash for block {block_number}");
    block_hash.expect("no substrate blockhash")
  }

  fn assert_builds_upon_is_expected(&self, expected: &IncrementalUnbalancedMerkleTree) {
    assert_eq!(BuildsUpon::get(&self.db).as_ref(), Some(expected));
  }

  // Assert everything that changed or should have changed after a simple task iteration run with linear blocks
  // (substrate block hashes are set and builds upon is expected)
  fn assert_task_iteration_per_block(&self, block_number: u64) -> BlockHash {
    let block_hash = self.assert_substrate_block_hash_exists(block_number);
    self.assert_builds_upon_is_expected(&self.serai.builds_upon);
    block_hash
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

  fn assert_task_iterations_with_no_events_ran(&mut self, block_numbers: (u64, u64)) {
    let start_block = block_numbers.0;
    let end_block = block_numbers.1;

    for block_number in start_block..=end_block {
      self.assert_task_iteration_per_block(block_number);
      self.assert_block_events_is_expected(BlockEventData {
        block_number,
        has_events: HasEvents::No,
      });
    }

    self.assert_scan_cosign_from_is_expected(end_block + 1);
  }

  /// Asserts that block 1 was processed successfully but block 2 failed.
  /// Takes the expected `builds_upon` value (state after block 1 was processed).
  fn assert_block_1_succeeded_block_2_failed(
    &self,
    expected_builds_upon: &IncrementalUnbalancedMerkleTree,
  ) {
    let getter = &self.db;

    assert!(SubstrateBlockHash::get(getter, 1).is_some());
    assert!(SubstrateBlockHash::get(getter, 2).is_none());

    // BuildsUpon should reflect state after block 1 (before block 2 failed)
    self.assert_builds_upon_is_expected(expected_builds_upon);

    assert_eq!(BlockEvents::peek(getter).expect("missing block events").block_number, 1);
    // Next ScanCosignFrom is still block 2 since it failed and must be re-ran
    assert_eq!(ScanCosignFrom::get(getter).expect("missing scan cosign from"), 2);
  }

  fn assert_stakes_is_expected(
    &self,
    network: ExternalNetworkId,
    validator: SeraiAddress,
    expected: Option<Amount>,
  ) {
    assert_eq!(Stakes::get(&self.db, network, validator), expected);
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

  #[allow(dead_code)]
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

  #[allow(dead_code)]
  fn assert_latest_global_session_intended(&self, expected: Option<[u8; 32]>) {
    assert_eq!(LatestGlobalSessionIntended::get(&self.db), expected);
  }

  #[allow(dead_code)]
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

  /// Asserts that a notable block was processed correctly, verifying:
  /// - Substrate block hash and builds_upon are set
  /// - BlockEvents has the correct event type:
  ///   - HasEvents::No for the first notable block (no prior session to cosign it)
  ///   - HasEvents::Notable for subsequent notable blocks
  /// - A new GlobalSession was created and stored
  /// - GlobalSessionsLastBlock is set for the previous session (if one existed)
  /// - LatestGlobalSessionIntended is updated to the new session
  /// - GlobalSessionsChannel received the new session
  /// - IntendedCosigns are sent for the previous session's sets (if one existed)
  ///
  /// Returns the new session ID and session info for further assertions if needed.
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

    // Get session from channel (channels preserve order, so this gives us the session for this block)
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

  /// Asserts that a non-notable block (e.g., with burn events) was processed correctly, verifying:
  /// - Substrate block hash and builds_upon are set
  /// - BlockEvents has NonNotable for this block
  /// - IntendedCosigns are sent for the active session's sets (with notable=false)
  /// - ScanCosignFrom is set to the next block
  fn assert_task_iteration_per_block_with_non_notable_events_ran(&mut self, block_number: u64) {
    let block_hash = self.assert_task_iteration_per_block(block_number);
    self.assert_task_iteration_per_block_concluded(block_number, HasEvents::NonNotable);

    let active_session_id = LatestGlobalSessionIntended::get(&self.db)
      .expect("NonNotable block requires an active session from a prior notable block");

    // IntendedCosigns are sent for the active session's sets with notable=false
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
async fn intend_returns_false_with_no_blocks() {
  let test = Test::new();
  let mut task = test.into_intend_task();
  Test::assert_task_run_and_check_progress(&mut task, false).await;
}

#[tokio::test]
async fn intend_returns_false_with_genesis_block() {
  let mut test = Test::new();

  let genesis_hash = test.serai.make_block(0);
  test.serai.initialize_empty_events(genesis_hash);

  let mut task = test.into_intend_task();

  // In intend.rs let start_block_number = ScanCosignFrom::get(&self.db).unwrap_or(1);
  // will default to the 1st block, and without a greater serai.latest_finalized_block_number()
  // there will nothing to iterate, returning false as in "did not progress"
  Test::assert_task_run_and_check_progress(&mut task, false).await;
}

#[tokio::test]
async fn intend_returns_true_with_one_block() {
  let mut test = Test::new();

  let block1_hash = test.serai.make_block(1);
  test.serai.initialize_empty_events(block1_hash);

  let mut task = test.into_intend_task();

  // Should return true as in "did progress the new block"
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  test.assert_task_iteration_per_block_with_no_events_ran(1);
}

#[tokio::test]
async fn intend_returns_true_with_linear_blocks_with_no_events() {
  let mut test = Test::new();

  let block1_hash = test.serai.make_block(1);
  test.serai.initialize_empty_events(block1_hash);

  let block2_hash = test.serai.make_block(2);
  test.serai.initialize_empty_events(block2_hash);

  let block3_hash = test.serai.make_block(3);
  test.serai.initialize_empty_events(block3_hash);

  let mut task = test.into_intend_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  test.assert_task_iterations_with_no_events_ran((1, 3));
}

#[tokio::test]
async fn intend_errors_if_chain_is_not_linear() {
  let mut test = Test::new();

  let block1_hash = test.serai.make_block(1);
  test.serai.initialize_empty_events(block1_hash);

  // Capture builds_upon after block 1 (before block 2 modifies it)
  let builds_upon_after_block_1 = test.serai.builds_upon.clone();

  // Block #2 does not build upon block #1
  test.serai.builds_upon = IncrementalUnbalancedMerkleTree::new();

  let block2_hash = test.serai.make_block(2);
  test.serai.initialize_empty_events(block2_hash);

  let mut task = test.into_intend_task();
  Test::assert_task_failed(&mut task, "doesn't build upon").await;

  test.assert_block_1_succeeded_block_2_failed(&builds_upon_after_block_1);
}

#[tokio::test]
async fn intend_errors_if_block_not_found() {
  let mut test = Test::new();

  // Block 1 exists and can be fetched
  let block1_hash = test.serai.make_block(1);
  test.serai.initialize_empty_events(block1_hash);

  // Capture builds_upon after block 1 (before block 2 modifies it)
  let builds_upon_after_block_1 = test.serai.builds_upon.clone();

  // Block 2 exists in terms of finalization, but returns None when fetched
  test.serai.make_block(2);
  test.serai.set_block_not_found(2);

  let mut task = test.into_intend_task();
  Test::assert_task_failed(&mut task, "couldn't get block which should've been finalized").await;

  test.assert_block_1_succeeded_block_2_failed(&builds_upon_after_block_1);
}

#[tokio::test]
async fn intend_handles_rpc_error_on_block_fetch() {
  let mut test = Test::new();

  // Block 1 exists and can be fetched
  let block1_hash = test.serai.make_block(1);
  test.serai.initialize_empty_events(block1_hash);

  // Capture builds_upon after block 1 (before block 2 modifies it)
  let builds_upon_after_block_1 = test.serai.builds_upon.clone();

  // Block 2 exists in terms of finalization, but fetching it returns an error
  test.serai.make_block(2);
  test.serai.set_block_error(2, "connection refused");

  let mut task = test.into_intend_task();
  Test::assert_task_failed(&mut task, "RPC error fetching block").await;

  test.assert_block_1_succeeded_block_2_failed(&builds_upon_after_block_1);
}

#[tokio::test]
async fn intend_handles_rpc_error_on_events_fetch() {
  let mut test = Test::new();

  // Block 1 exists and can be fetched
  let block1_hash = test.serai.make_block(1);
  test.serai.initialize_empty_events(block1_hash);

  // Capture builds_upon after block 1 (before block 2 modifies it)
  let builds_upon_after_block_1 = test.serai.builds_upon.clone();

  // Block 2 exists in terms of finalization, but fetching it returns an error
  let block2_hash = test.serai.make_block(2);
  test.serai.set_events_error(block2_hash, "timeout");

  let mut task = test.into_intend_task();
  Test::assert_task_failed(&mut task, "RPC error fetching events").await;

  test.assert_block_1_succeeded_block_2_failed(&builds_upon_after_block_1);
}

#[tokio::test]
async fn intend_handles_rpc_error_on_latest_finalized() {
  let mut test = Test::new();

  // We need to add a block first so latest_finalized_block_number would normally succeed
  test.serai.make_block(1);

  // Create a wrapper that returns error for latest_finalized_block_number
  #[derive(Clone)]
  struct FailingSeraiRPC;
  impl SeraiRpc for FailingSeraiRPC {
    fn latest_finalized_block_number(&self) -> impl Send + Future<Output = Result<u64, String>> {
      async { Err("network error".to_string()) }
    }
    fn block_by_number(
      &self,
      _block: u64,
    ) -> impl Send + Future<Output = Result<Option<Block>, String>> {
      async { Ok(None) }
    }
    fn events(&self, _block: BlockHash) -> impl Send + Future<Output = Result<Events, String>> {
      async { Ok(Events::new()) }
    }
  }

  // Create a custom Serai that will fail on latest_finalized_block_number
  let mut task = CosignIntendTask { db: test.db.clone(), serai: FailingSeraiRPC };
  Test::assert_task_failed(&mut task, "RPC error fetching latest finalized").await;
}

#[tokio::test]
async fn intend_handles_allocation_events() {
  let mut test = Test::new();

  let validator1 = SeraiAddress([0x01; 32]);
  let validator2 = SeraiAddress([0x02; 32]);

  // Block 1: Allocations across multiple networks
  let allocations_block1 = [
    (validator1, ExternalNetworkId::Bitcoin, 50),
    (validator1, ExternalNetworkId::Bitcoin, 100),
    (validator2, ExternalNetworkId::Bitcoin, 200),
    (validator1, ExternalNetworkId::Ethereum, 150),
  ];
  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(block1_hash, events_from_allocations(&allocations_block1));

  // Block 2: More allocations
  let allocations_block2 =
    [(validator2, ExternalNetworkId::Ethereum, 75), (validator1, ExternalNetworkId::Bitcoin, 25)];
  let block2_hash = test.serai.make_block(2);
  test.serai.set_events(block2_hash, events_from_allocations(&allocations_block2));

  let mut task = test.into_intend_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  let all_allocations: Vec<_> =
    allocations_block1.iter().chain(allocations_block2.iter()).copied().collect();
  test.assert_stakes_from_allocations_is_expected(&all_allocations);

  // Both blocks have only allocation events (no SetKeys, no burn) -> HasEvents::No
  test.assert_task_iterations_with_no_events_ran((1, 2));
}

#[tokio::test]
async fn intend_handles_deallocation_event() {
  let mut test = Test::new();

  let validator = SeraiAddress([0x01; 32]);

  // Block 1: Allocate then deallocate some
  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(
    block1_hash,
    vec![
      // Allocate first
      allocation_event(validator, NetworkId::External(ExternalNetworkId::Bitcoin), 100),
      // Deallocate some
      deallocation_event(validator, NetworkId::External(ExternalNetworkId::Bitcoin), 30),
    ],
  );

  // Block 2: Deallocate more than remaining to test saturation
  let block2_hash = test.serai.make_block(2);
  test.serai.set_events(
    block2_hash,
    vec![
      // Deallocate more than remaining (70 left, deallocating 100)
      deallocation_event(validator, NetworkId::External(ExternalNetworkId::Bitcoin), 100),
    ],
  );

  // Create task after all blocks are set up
  let mut task = test.into_intend_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  test.assert_stakes_is_expected(ExternalNetworkId::Bitcoin, validator, Some(Amount(0)));

  // Both blocks have only allocation/deallocation events (no SetKeys, no burn) -> HasEvents::No
  test.assert_task_iterations_with_no_events_ran((1, 2));
}

#[tokio::test]
async fn intend_errors_if_notable_block_has_no_stake() {
  let mut test = Test::new();

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
      set_decided_event(vset0, validator1),
      set_keys_event(set0, 1),
    ],
  );

  // Block 2: SetDecided and SetKeys for new session with validator2 who has no allocations -> 0 stake
  let block2_hash = test.serai.make_block(2);
  test
    .serai
    .set_events(block2_hash, vec![set_decided_event(vset1, validator2), set_keys_event(set1, 2)]);

  let mut task = test.into_intend_task();
  Test::assert_task_failed(&mut task, "had 0 stake").await;
}

#[tokio::test]
async fn intend_handles_set_decided_event() {
  let mut test = Test::new();

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
    vec![Event::ValidatorSets(validator_sets::Event::SetDecided {
      set: vset0_btc,
      validators: vec![
        (validator1, KeyShares(1)),
        (validator2, KeyShares(2)),
        (validator3, KeyShares(3)),
      ],
    })],
  );

  // Block 2: SetDecided for Ethereum with different validators
  let block2_hash = test.serai.make_block(2);
  test.serai.set_events(
    block2_hash,
    vec![Event::ValidatorSets(validator_sets::Event::SetDecided {
      set: vset0_eth,
      validators: vec![(validator1, KeyShares(2)), (validator2, KeyShares(3))],
    })],
  );

  let mut task = test.into_intend_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  // Verify validators are stored for each set
  test.assert_validators_is_expected(set0_btc, Some(vec![validator1, validator2, validator3]));
  test.assert_validators_is_expected(set0_eth, Some(vec![validator1, validator2]));

  // SetDecided alone doesn't make a block notable (only SetKeys does) -> HasEvents::No
  test.assert_task_iterations_with_no_events_ran((1, 2));
}

#[tokio::test]
async fn intend_handles_set_keys_event() {
  let mut test = Test::new();

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
      Event::ValidatorSets(validator_sets::Event::SetDecided {
        set: vset0,
        validators: vec![(validator1, KeyShares(1)), (validator2, KeyShares(2))],
      }),
      set_keys_event(set0, 1),
    ],
  );

  // Block 2: Second SetKeys (creates session 1)
  let block2_hash = test.serai.make_block(2);
  test.serai.set_events(
    block2_hash,
    vec![
      Event::ValidatorSets(validator_sets::Event::SetDecided {
        set: vset1,
        validators: vec![(validator1, KeyShares(2)), (validator2, KeyShares(1))],
      }),
      set_keys_event(set1, 2),
    ],
  );

  let mut task = test.into_intend_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  let expected_set = Set { session: Session(1), key: Public([2u8; 32]), stake: Amount(300) };
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
async fn intend_handles_burn_with_instruction_events() {
  let mut test = Test::new();

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
  events.push(Event::ValidatorSets(validator_sets::Event::SetDecided {
    set: vset0,
    validators: vec![(validator1, KeyShares(1)), (validator2, KeyShares(2))],
  }));
  events.push(set_keys_event(set0, 1));
  test.serai.set_events(block1_hash, events);

  // Block 2: Burn event makes block NonNotable (with additional allocations)
  let allocations_block2 = [(validator1, ExternalNetworkId::Bitcoin, 50)];
  let block2_hash = test.serai.make_block(2);
  let mut events2 = events_from_allocations(&allocations_block2);
  events2.push(burn_with_instruction_event(validator1));
  test.serai.set_events(block2_hash, events2);

  let mut task = test.into_intend_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

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
async fn intend_ignores_non_validator_sets_events() {
  let mut test = Test::new();

  let vset0 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(0) };
  let vset1 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Ethereum), session: Session(0) };

  // Block 1: System event (outer _ => continue) and AcceptedHandover (inner _ => continue)
  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(
    block1_hash,
    vec![
      Event::System(system::Event::TransactionSuccess),
      Event::ValidatorSets(validator_sets::Event::AcceptedHandover { set: vset0 }),
    ],
  );

  // Block 2: More ignored events on different network
  let block2_hash = test.serai.make_block(2);
  test.serai.set_events(
    block2_hash,
    vec![
      Event::System(system::Event::TransactionSuccess),
      Event::ValidatorSets(validator_sets::Event::AcceptedHandover { set: vset1 }),
    ],
  );

  let mut task = test.into_intend_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  // Both blocks have only ignored events -> HasEvents::No
  test.assert_task_iterations_with_no_events_ran((1, 2));
}

#[tokio::test]
async fn intend_ignores_serai_network_events() {
  let mut test = Test::new();

  let validator = SeraiAddress([0x01; 32]);

  let vset_serai = ValidatorSet { network: NetworkId::Serai, session: Session(0) };

  // Block 1: Allocation and Deallocation with NetworkId::Serai
  let block1_hash = test.serai.make_block(1);
  test.serai.set_events(
    block1_hash,
    vec![
      // Allocation with Serai network -> continue (line 154)
      allocation_event(validator, NetworkId::Serai, 100),
      // Deallocation with Serai network -> continue (line 159)
      deallocation_event(validator, NetworkId::Serai, 50),
    ],
  );

  // Block 2: SetDecided with NetworkId::Serai
  let block2_hash = test.serai.make_block(2);
  test.serai.set_events(
    block2_hash,
    vec![Event::ValidatorSets(validator_sets::Event::SetDecided {
      set: vset_serai,
      validators: vec![(validator, KeyShares(1))],
    })],
  );

  let mut task = test.into_intend_task();
  Test::assert_task_run_and_check_progress(&mut task, true).await;

  // Verify no stakes were recorded for Serai network (allocations were ignored)
  // Stakes::get only works with ExternalNetworkId, so we can't directly check Serai
  // But we can verify the blocks were processed with no notable events
  test.assert_task_iterations_with_no_events_ran((1, 2));
}
