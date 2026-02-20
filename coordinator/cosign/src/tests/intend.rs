use std::{collections::HashMap, sync::Arc, time::Duration};

use rand_core::{OsRng, RngCore};

use serai_db::{Db as _, DbTxn, MemDb};

use serai_simulator_node::{SimulatorNode, SimulatorState};

use serai_client_serai::{
  Serai,
  abi::{
    Event, coins,
    primitives::{
      BlockHash,
      address::{ExternalAddress, SeraiAddress},
      balance::{Amount, ExternalBalance},
      coin::ExternalCoin,
      crypto::{ExternalKey, KeyPair, Public},
      instructions::{OutInstruction, OutInstructionWithBalance},
      merkle::IncrementalUnbalancedMerkleTree,
      network_id::{ExternalNetworkId, NetworkId},
      validator_sets::{ExternalValidatorSet, KeyShares, Session, ValidatorSet},
    },
    validator_sets,
  },
};

use crate::{intend::*, tests::*, *};

use super::SERAI_NODE_LOCK;

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

/// Generic test struct for intend tests.
/// Uses `FakeSerai` for mock tests and can be extended for live tests.
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

impl IntendTestStruct {
  fn assert_substrate_block_hash_exists(&self, block_number: u64) -> BlockHash {
    let block_hash = SubstrateBlockHash::get(&self.db, block_number);
    assert!(block_hash.is_some(), "no substrate blockhash for block {block_number}");
    block_hash.expect("no substrate blockhash")
  }

  fn assert_builds_upon_is_expected(&self, expected: &IncrementalUnbalancedMerkleTree) {
    assert_eq!(BuildsUpon::get(&self.db).as_ref(), Some(expected));
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

  fn assert_task_iteration_per_block_concluded(
    &mut self,
    block_number: u64,
    has_events: HasEvents,
  ) {
    self.assert_block_events_is_expected(BlockEventData { block_number, has_events });
    self.assert_scan_cosign_from_is_expected(block_number + 1);
  }

  /// Assert that the task processed `block_number` correctly (no events).
  fn assert_task_iteration_per_block_with_no_events_ran(
    &mut self,
    block_number: u64,
    expected_builds_upon: &IncrementalUnbalancedMerkleTree,
  ) {
    self.assert_substrate_block_hash_exists(block_number);
    self.assert_builds_upon_is_expected(expected_builds_upon);
    self.assert_task_iteration_per_block_concluded(block_number, HasEvents::No);
  }

  /// Assert blocks were processed up to (but not including) `failed_block`.
  fn assert_task_iterations_with_no_events_failed_at(
    &mut self,
    failed_block: u64,
    expected_builds_upon: &IncrementalUnbalancedMerkleTree,
  ) {
    self.assert_task_iteration_per_block_with_no_events_ran(failed_block - 1, expected_builds_upon);
  }
}

/// Create a [`SimulatorNode`] and an [`IntendTestStruct`] connected to it.
async fn setup_mock_test() -> (SimulatorNode, IntendTestStruct) {
  let node = SimulatorNode::start(SimulatorState::default()).await;
  let serai = Arc::new(Serai::new(node.url()).unwrap());
  (node, IntendTestStruct { serai, db: MemDb::new() })
}

#[tokio::test]
async fn iterates_serai_blocks() {
  let _lock = SERAI_NODE_LOCK.lock().await;
  serai_test_harness::serai_test(async |serai| {
    let serai = Arc::new(serai);
    let mut task = CosignIntendTask { db: MemDb::new(), serai: serai.clone() };

    // First run processes all currently finalized blocks (and/or at least genesis), progress = true
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    // The task has now consumed everything up to latest_finalized. Record that height.
    let height_after_first_run = serai.latest_finalized_block_number().await.unwrap();

    // Second run: no new blocks beyond what was just processed, progress = false
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;

    // Wait for at least 3 new finalized blocks beyond the first run's height
    let target = height_after_first_run + 3;
    serai_test_harness::wait_for_blocks(&serai, target, Duration::from_secs(60)).await;

    // Third run: processes multiple new blocks, progress = true
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
  })
  .await;
}

mod errors {
  use super::*;

  #[tokio::test]
  async fn errors_if_chain_is_not_linear() {
    let (node, mut test) = setup_mock_test().await;

    node.make_block(0, vec![]).await;
    node.make_block(1, vec![]).await;

    let builds_upon_after_block_1 = node.builds_upon().await;
    node.make_non_linear_block(2, vec![]).await;

    let mut task = test.into_task();

    TaskTest::assert_task_run_and_failed_with(&mut task, "doesn't build upon").await;

    // Consume block 0's channel entry before checking block 1
    test.assert_block_events_is_expected(BlockEventData {
      block_number: 0,
      has_events: HasEvents::No,
    });
    test.assert_task_iterations_with_no_events_failed_at(2, &builds_upon_after_block_1);

    // Now fix the chain: remove the broken block 2 and recreate it properly
    node.remove_block(2).await;
    node.make_block(2, vec![]).await;

    let mut task = test.into_task();

    // Re-run the task, block 2 properly builds upon block 1
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    // block 1 was already asserted and cleared from queue, assert only block 2 now
    let builds_upon_after_block_2 = node.builds_upon().await;
    test.assert_task_iteration_per_block_with_no_events_ran(2, &builds_upon_after_block_2);
  }

  #[tokio::test]
  async fn errors_if_block_not_found() {
    let (node, mut test) = setup_mock_test().await;

    node.make_block(0, vec![]).await;
    node.make_block(1, vec![]).await;

    // Capture builds_upon after block 1
    let builds_upon_after_block_1 = node.builds_upon().await;

    // Block 2 exists in terms of finalization, but returns None when fetched
    node.make_block(2, vec![]).await;
    node.set_block_missing(2).await;

    let mut task = test.into_task();
    TaskTest::assert_task_run_and_failed_with(
      &mut task,
      "couldn't get block which should've been finalized",
    )
    .await;

    test.assert_block_events_is_expected(BlockEventData {
      block_number: 0,
      has_events: HasEvents::No,
    });
    test.assert_task_iterations_with_no_events_failed_at(2, &builds_upon_after_block_1);

    node.clear_block_missing(2).await;

    let mut task = test.into_task();

    // Re-run the task, block 2 now fetched and processed
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    let builds_upon = node.builds_upon().await;
    test.assert_task_iteration_per_block_with_no_events_ran(2, &builds_upon);
  }

  #[tokio::test]
  async fn handles_rpc_error_on_block_fetch() {
    let (node, mut test) = setup_mock_test().await;

    node.make_block(0, vec![]).await;
    node.make_block(1, vec![]).await;

    // Capture builds_upon after block 1
    let builds_upon_after_block_1 = node.builds_upon().await;

    // Block 2 exists in terms of finalization, but fetching it returns an error
    node.make_block(2, vec![]).await;
    node.set_block_number_error("blockchain/block", 2, "connection refused").await;

    let mut task = test.into_task();
    TaskTest::assert_task_run_and_failed_with(&mut task, "RPC error fetching block").await;

    test.assert_block_events_is_expected(BlockEventData {
      block_number: 0,
      has_events: HasEvents::No,
    });
    test.assert_task_iterations_with_no_events_failed_at(2, &builds_upon_after_block_1);

    node.clear_block_number_error("blockchain/block", 2).await;

    let mut task = test.into_task();

    // Re-run the task, block 2 now fetched and processed
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    let builds_upon = node.builds_upon().await;
    test.assert_task_iteration_per_block_with_no_events_ran(2, &builds_upon);
  }

  #[tokio::test]
  async fn handles_rpc_error_on_events_fetch() {
    let (node, mut test) = setup_mock_test().await;

    node.make_block(0, vec![]).await;
    node.make_block(1, vec![]).await;

    // Capture builds_upon after block 1
    let builds_upon_after_block_1 = node.builds_upon().await;

    // Block 2 exists in terms of finalization, but fetching its events returns an error
    let block2_hash = node.make_block(2, vec![]).await;
    node.set_block_hash_error("blockchain/events", block2_hash, "timeout").await;

    let mut task = test.into_task();
    TaskTest::assert_task_run_and_failed_with(&mut task, "RPC error fetching events").await;

    test.assert_block_events_is_expected(BlockEventData {
      block_number: 0,
      has_events: HasEvents::No,
    });
    test.assert_task_iterations_with_no_events_failed_at(2, &builds_upon_after_block_1);

    node.clear_block_hash_error("blockchain/events", block2_hash).await;

    let mut task = test.into_task();

    // Re-run the task, block 2 events now fetched and processed
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    let builds_upon = node.builds_upon().await;
    test.assert_task_iteration_per_block_with_no_events_ran(2, &builds_upon);
  }

  #[tokio::test]
  async fn errors_if_set_decided_has_empty_validators() {
    let (node, test) = setup_mock_test().await;

    // Block 0: no events
    node.make_block(0, vec![]).await;

    // Block 1: SetDecided with an external network but an empty validator list
    let empty_set_decided = set_decided_event(
      ValidatorSet {
        network: NetworkId::External(ExternalNetworkId::Bitcoin),
        session: Session(0),
      },
      vec![],
    );
    node.make_block(1, vec![vec![empty_set_decided]]).await;

    let mut task = test.into_task();
    TaskTest::assert_task_run_and_failed_with(
      &mut task,
      "validator set from Event::SetDecided was empty",
    )
    .await;
  }

  #[tokio::test]
  async fn handles_rpc_error_on_latest_finalized() {
    let (node, mut test) = setup_mock_test().await;

    node.make_block(0, vec![]).await;
    node.make_block(1, vec![]).await;
    node.set_error("blockchain/latest_finalized_block_number", "network error").await;

    let mut task = test.into_task();
    TaskTest::assert_task_run_and_failed_with(&mut task, "RPC error fetching latest finalized")
      .await;

    node.clear_error("blockchain/latest_finalized_block_number").await;

    let mut task = test.into_task();

    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    test.assert_block_events_is_expected(BlockEventData {
      block_number: 0,
      has_events: HasEvents::No,
    });
    let builds_upon = node.builds_upon().await;
    test.assert_task_iteration_per_block_with_no_events_ran(1, &builds_upon);
  }
}
