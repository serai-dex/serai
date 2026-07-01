use std::collections::HashMap;
use futures::FutureExt as _;
use rand::RngCore as _;
use rand_core::OsRng;
use serai_cosign::Cosigning;
use serai_cosign::test_helpers::random_global_cosigning_session_id;
use serai_primitives::{
  instructions::OutInstructionWithBalance, test_helpers::random_external_network_id,
  validator_sets::Session,
};
use serai_task::{FuturesRangeProcessor as _, test_helpers::IntoMockSerai};
#[allow(unused_imports)]
use serai_mock_rpc::event_fuzzer::in_instructions as in_instructions_events;
use serai_mock_rpc::block_events_fuzzer::BlockEventsFuzzer;

use serai_abi::{Block, Event, validator_sets::ReportedSlashes};
use serai_client_serai::{
  Serai,
  abi::{self, primitives::network_id::ExternalNetworkId},
};

use crate::{
  Canonical,
  canonical::{CanonicalEventStream, ScanCanonicalBlocksFrom, last_indexed_batch_id},
};
use super::*;

use messages::substrate::{CoordinatorMessage, ExecutedBatch, InInstructionResult};

struct CanonicalTestStruct {
  serai: Arc<Serai>,
  db: MemDb,
}

serai_task::impl_serai_task_test_struct!(CanonicalTestStruct);

impl IntoTask for CanonicalTestStruct {
  type Task = CanonicalEventStream<MemDb>;

  fn task(&self) -> Self::Task {
    CanonicalEventStream::new(self.db.clone(), self.serai.clone())
  }
}

impl IntoMockSerai for CanonicalTestStruct {}

fn verify_db_invariants_for_network_and_events(
  db: &mut MemDb,
  networks: Option<Vec<ExternalNetworkId>>,
  events: &[Vec<Event>],
  blocks: &[Block],
) {
  let num_blocks = events.len();
  if num_blocks > 0 {
    // ScanCanonicalBlocksFrom should point to the block after the last processed
    assert_eq!(
      ScanCanonicalBlocksFrom::get(db),
      Some(u64::try_from(num_blocks).unwrap()),
      "ScanCanonicalBlocksFrom should be {num_blocks} after processing blocks 0..={num_blocks}"
    );
  } else {
    assert!(
      ScanCanonicalBlocksFrom::get(db).is_none(),
      "ScanCanonicalBlocksFrom should be None after not processing any blocks",
    );
  }

  let mut txn = db.txn();
  let mut last_batch_ids = HashMap::new();

  // For each network, start asserting every one of its sent messages
  // messages are stored as a queue per network, every event added
  // is stored one after the other
  for network in &networks.unwrap_or_else(|| ExternalNetworkId::all().collect()) {
    let get_next_msg = |txn: &mut _| Canonical::try_recv(txn, *network);

    let mut slashes_reported_sessions: Vec<Session> = Vec::new();

    // For all events in all blocks find the ones for the current network
    for (block_number, block_events) in events.iter().enumerate() {
      let expected_serai_time = blocks[block_number].header.unix_time_in_millis() / 1000;

      let mut set_keys_events = Vec::new();
      let mut slashes_events = Vec::new();
      let mut batch_event: Option<&serai_abi::in_instructions::Event> = None;
      let mut burns = Vec::new();

      for event in block_events {
        #[expect(clippy::wildcard_enum_match_arm)]
        match event {
          #[expect(clippy::wildcard_enum_match_arm)]
          serai_abi::Event::ValidatorSets(vset_event) => match vset_event {
            abi::validator_sets::Event::SetKeys { set, .. } if &set.network == network => {
              set_keys_events.push(vset_event);
            }
            abi::validator_sets::Event::Slashes(ReportedSlashes::ExternalValidatorSet(set))
              if &set.network == network =>
            {
              slashes_events.push(vset_event);
            }
            _ => {}
          },
          serai_abi::Event::InInstructions(this_batch) => {
            let abi::in_instructions::Event::Batch { network: this_network, .. } = this_batch;

            if this_network == network {
              assert!(batch_event.is_none(), "double batch");
              batch_event = Some(this_batch);
            }
          }
          serai_abi::Event::Coins(burn) => {
            let abi::coins::Event::BurnWithInstruction { instruction, .. } = burn else {
              unreachable!("BurnWithInstruction event wasn't a BurnWithInstruction event: {burn:?}")
            };

            if &instruction.balance.coin.network() == network {
              burns.push(event);
            }
          }
          _ => {}
        }
      }

      for set_keys_event in set_keys_events {
        let abi::validator_sets::Event::SetKeys { set, key_pair } = set_keys_event else {
          unreachable!("`SetKeys` event wasn't a `SetKeys` event: {set_keys_event:?}");
        };

        if let Some(CoordinatorMessage::SetKeys { serai_time, session, key_pair: msg_key_pair }) =
          get_next_msg(&mut txn)
        {
          assert_eq!(serai_time, expected_serai_time);
          assert_eq!(session, set.session);
          assert_eq!(msg_key_pair, *key_pair);
        }

        if let Some(historical_session) = set.session.0.checked_sub(2) {
          let historical_session = Session(historical_session);
          if !slashes_reported_sessions.contains(&historical_session) {
            if let Some(CoordinatorMessage::SlashesReported { session }) = get_next_msg(&mut txn) {
              assert_eq!(session, historical_session);
              slashes_reported_sessions.push(historical_session);
            }
          }
        }
      }

      for slash_event in slashes_events {
        let abi::validator_sets::Event::Slashes(reported_slashes) = slash_event else {
          unreachable!("`Slashes` event wasn't a `Slashes` event: {slash_event:?}");
        };

        if let Some(CoordinatorMessage::SlashesReported { session }) = get_next_msg(&mut txn) {
          match reported_slashes {
            ReportedSlashes::SeraiValidator(_) => {}
            ReportedSlashes::ExternalValidatorSet(set) => {
              assert_eq!(session, set.session);
              slashes_reported_sessions.push(set.session);
            }
          }
        }
      }

      if batch_event.is_some() || !burns.is_empty() {
        if let Some(msg) = get_next_msg(&mut txn) {
          let CoordinatorMessage::Block {
            serai_block_number,
            batch: ref msg_batch,
            burns: ref msg_burns,
          } = msg
          else {
            panic!("");
          };
          assert_eq!(
            serai_block_number,
            u64::try_from(block_number).unwrap(),
            "Block number mismatch for {network:?}"
          );
          let expected_batch = batch_event.map(|be| {
            let abi::in_instructions::Event::Batch {
              id,
              publishing_session,
              external_network_block_hash,
              in_instructions_hash,
              in_instruction_results,
              ..
            } = be;
            last_batch_ids.insert(*network, *id);
            ExecutedBatch {
              id: *id,
              publisher: *publishing_session,
              external_network_block_hash: external_network_block_hash.0,
              in_instructions_hash: *in_instructions_hash,
              in_instruction_results: in_instruction_results
                .iter()
                .map(|bit| {
                  if *bit {
                    InInstructionResult::Succeeded
                  } else {
                    InInstructionResult::Failed
                  }
                })
                .collect(),
            }
          });
          assert_eq!(
            msg_batch, &expected_batch,
            "batch mismatch for {network:?} at block {block_number}"
          );

          let expected_burns: Vec<OutInstructionWithBalance> = burns
            .iter()
            .map(|burn_event| {
              let serai_abi::Event::Coins(abi::coins::Event::BurnWithInstruction {
                instruction,
                ..
              }) = burn_event
              else {
                unreachable!(
                  "BurnWithInstruction event wasn't a BurnWithInstruction event: {burn_event:?}"
                )
              };
              instruction.clone()
            })
            .collect();
          assert_eq!(
            msg_burns, &expected_burns,
            "burns mismatch for {network:?} at block {block_number}"
          );
        }
      }
    }

    assert_eq!(
      &last_indexed_batch_id(&txn, *network).unwrap_or(0),
      last_batch_ids.get(network).unwrap_or(&0)
    );

    // Iterated over all events on all blocks for this network
    // Message queue should be empty, next message is None
    assert!(get_next_msg(&mut txn).is_none());
  }

  // `txn` is dropped here without `.commit()`. The channel is left unchanged.
  // retries have to iterate over all block/events & message elements again
  // txn.commit();
}

mod errors {
  use super::*;

  #[tokio::test]
  async fn handles_faulted_session() {
    let (mock_serai, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
    let (block_hashes, _, _) = mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;
    let mut txn = task_test.db.txn();
    seed_cosigned_blocks(&mut txn, &block_hashes, &[]);
    {
      let mut txn = task_test.db.txn();
      serai_cosign::test_helpers::set_faulted_session(
        &mut txn,
        &random_global_cosigning_session_id(&mut OsRng),
      );
      txn.commit();
    }

    // Does not progress on existing FaultedSession for block
    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(&mut task, "Error getting latest cosigned block number")
        .await;
    }
    verify_db_invariants_for_network_and_events(&mut task_test.db, None, &[], &[]);
  }

  #[tokio::test]
  #[should_panic(
    expected = "iterating to latest cosigned block but couldn't get cosigned block number"
  )]
  async fn panics_on_cosigned_block_no_latest_is_none() {
    let (mock_serai, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
    let (block_hashes, _, _) = mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;
    let mut txn = task_test.db.txn();
    seed_cosigned_blocks(&mut txn, &block_hashes, &[]);
    txn.commit();

    // Simulate task.run_iteration(), calling latest_cosigned_block_number is fine yet
    let _latest_cosigned_block_number =
      Cosigning::<MemDb>::latest_cosigned_block_number(&task_test.db)
        .expect("Latest cosigned block number should not Error yet");

    // Delete the seeded block so cosigned_block(n) returns Ok(None)
    {
      let mut txn = task_test.db.txn();
      serai_cosign::test_helpers::del_substrate_block_hash(&mut txn, 0);
      serai_cosign::test_helpers::del_latest_cosigned_block_number(&mut txn);
      txn.commit();
    }

    // fetch_item is called for block_number=0, previous latest=0 existed and
    // passed calling latest_cosigned_block_number, but now was deleted
    // so will trigger the panic
    let _ = task_test.task().fetch_item(0).await;
  }

  #[tokio::test]
  #[should_panic(
    expected = "iterating to latest cosigned block but couldn't get cosigned block number"
  )]
  async fn panics_on_cosigned_block_greater_than_latest_is_none() {
    let (_, mut task_test) = CanonicalTestStruct::setup_mock_test().await;

    // Seed only block 0 = latest is 0
    let mut txn = task_test.db.txn();
    seed_cosigned_blocks(&mut txn, &[(0, BlockHash([0u8; 32]))], &[]);
    txn.commit();

    // Simulate task.run_iteration(), calling latest_cosigned_block_number is fine yet
    let _latest_cosigned_block_number =
      Cosigning::<MemDb>::latest_cosigned_block_number(&task_test.db)
        .expect("Latest cosigned block number should not Error yet");

    // fetch_item is called for block_number=1, but latest=0 so will trigger the panic
    let _ = task_test.task().fetch_item(1).await;
  }

  #[tokio::test]
  async fn panics_on_cosigned_block_no_substrate_blockhash() {
    let (mock_serai, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
    // Block 1 is missing from being indexed as cosigned, here it skips from 0 to 2
    let block_hashes = [
      (0, mock_serai.add_block_with_events(vec![]).await.0),
      (2, mock_serai.add_block_with_events(vec![]).await.0),
    ];
    let mut txn = task_test.db.txn();
    seed_cosigned_blocks(&mut txn, &block_hashes, &[]);
    txn.commit();

    let result = std::panic::AssertUnwindSafe(async {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
    })
    .catch_unwind()
    .await;

    let err = result.expect_err("should panic trying to iterate to block 1 which wasn't indexed");
    assert!(panic_message(&err).contains("cosigned the block 1 but didn't index it"),);
  }

  #[tokio::test]
  async fn fetch_item_errors_when_session_faults_after_first_check() {
    let (mock_serai, mut task_test) = CanonicalTestStruct::setup_mock_test().await;

    // Seed one cosigned block so latest_cosigned_block_number returns Some(0)
    let (block_hashes, _, _) = mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;
    let mut txn = task_test.db.txn();
    seed_cosigned_blocks(&mut txn, &block_hashes, &[]);
    txn.commit();

    // Simulate task.run_iteration() was called
    let _latest_cosigned_block_number =
      Cosigning::<MemDb>::latest_cosigned_block_number(&task_test.db)
        .expect("Latest cosigned block number should not Error yet");

    // Inject the fault into the shared DB after run_iteration is called, simulating the race
    {
      let mut txn = task_test.db.txn();
      serai_cosign::test_helpers::set_faulted_session(
        &mut txn,
        &random_global_cosigning_session_id(&mut OsRng),
      );
      txn.commit();
    }

    // fetch_item is called and cosigned_block now reads the faulted DB and returns Error
    let mut task = task_test.task();
    assert!(
      matches!(task.fetch_item(0).await, Err(ref e) if e == "cosigning process faulted"),
      "fetch_item must propagate Faulted when session faults between the \
          two latest_cosigned_block_number calls"
    );

    // Task continues failing on next iterations
    {
      TaskTest::task_runs_and_fails_with(&mut task, "Error getting latest cosigned block number")
        .await;
    }
    verify_db_invariants_for_network_and_events(&mut task_test.db, None, &[], &[]);
  }

  #[tokio::test]
  async fn handles_serai_block_rpc_error() {
    let (mock_serai, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
    let (block_hashes, all_events, all_blocks) =
      mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 3).await;
    let mut txn = task_test.db.txn();
    seed_cosigned_blocks(&mut txn, &block_hashes, &all_events);
    txn.commit();

    mock_serai.set_block_number_error("blockchain/block", 1, "connection refused").await;

    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching block").await;
    }
    // current latest is block 1
    let block0_events = all_events.first().unwrap().clone();
    let block0_block = all_blocks.first().cloned().unwrap();
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      None,
      &[block0_events],
      &[block0_block],
    );

    mock_serai.clear_all_errors().await;

    // No more errors, progresses normallly
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    // new latest is block 3
    verify_db_invariants_for_network_and_events(&mut task_test.db, None, &all_events, &all_blocks);
  }

  #[tokio::test]
  async fn panics_on_serai_block_none_from_serai() {
    let (mock_serai, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
    let (block_hashes, _, _) = mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;
    let mut txn = task_test.db.txn();
    seed_cosigned_blocks(&mut txn, &block_hashes, &[]);
    txn.commit();

    mock_serai.remove_block(0).await;

    let result = std::panic::AssertUnwindSafe(async {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
    })
    .catch_unwind()
    .await;

    let err = result.expect_err("should panic when the Serai node is missing a cosigned block");
    assert!(panic_message(&err).contains("Serai node didn't have block"),);
  }

  #[tokio::test]
  async fn handles_serai_events_rpc_error() {
    let (mock_serai, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
    let (block_hashes, all_events, all_blocks) =
      mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 3).await;
    let mut txn = task_test.db.txn();
    seed_cosigned_blocks(&mut txn, &block_hashes, &all_events);
    txn.commit();

    mock_serai.set_block_hash_error("blockchain/events", block_hashes[1].1, "timeout").await;

    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching block events").await;
    }
    // current latest is block 1
    let block1_events = all_events.first().unwrap().clone();
    let block1_block = all_blocks.first().cloned().unwrap();
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      None,
      &[block1_events],
      &[block1_block],
    );

    mock_serai.clear_all_errors().await;

    // No more errors, progresses normallly
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    // new latest is block 3
    verify_db_invariants_for_network_and_events(&mut task_test.db, None, &all_events, &all_blocks);
  }

  #[tokio::test]
  async fn panics_on_multiple_batches_per_network_on_block() {
    let (mock_serai, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
    let network = random_external_network_id(&mut OsRng);
    let session = serai_abi::primitives::validator_sets::Session(OsRng.next_u32());
    let block_hash = [0u8; 32];
    let empty_bitvec = serai_primitives::BitVec::<
      { serai_abi::in_instructions::IN_INSTRUCTION_RESULTS_BOUND },
    >::try_from(bitvec::vec::BitVec::<u8, bitvec::order::Lsb0>::new())
    .unwrap();

    // Create two batches for the SAME network with the same batch ID (0)
    // to trigger the "multiple batches for the same network" assertion.
    // id=0 is used so that id.checked_sub(1) = None, matching the initial
    // NetworksCanonicalLastIndexedBatchId state for a fresh network.
    let batch1 = serai_mock_rpc::events::in_instructions::batch(
      network,
      session,
      0,
      serai_primitives::BlockHash(block_hash),
      [0u8; 32],
      empty_bitvec.clone(),
    );
    let batch2 = serai_mock_rpc::events::in_instructions::batch(
      network,
      session,
      0,
      serai_primitives::BlockHash(block_hash),
      [0u8; 32],
      empty_bitvec,
    );

    let (block_hash, events, _) =
      mock_serai.add_block_with_events(vec![vec![batch1, batch2]]).await;
    let mut txn = task_test.db.txn();
    seed_cosigned_blocks(&mut txn, &[(0, block_hash)], &[events]);
    txn.commit();

    let result = std::panic::AssertUnwindSafe(async {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
    })
    .catch_unwind()
    .await;

    let err =
      result.expect_err("should panic on multiple batches for same network on the same block");
    assert!(panic_message(&err).contains("Serai block had multiple batches for the same network"));
  }

  #[tokio::test]
  async fn panics_on_next_batch_non_increment() {
    let empty_bitvec = serai_primitives::BitVec::<
      { serai_abi::in_instructions::IN_INSTRUCTION_RESULTS_BOUND },
    >::try_from(bitvec::vec::BitVec::<u8, bitvec::order::Lsb0>::new())
    .unwrap();

    // Case 1: Two batches with the same ID on different blocks (duplicate)
    {
      let (mock_serai, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
      let network = random_external_network_id(&mut OsRng);
      let session = serai_abi::primitives::validator_sets::Session(OsRng.next_u32());
      let id = OsRng.next_u32();
      let block_hash = [0u8; 32];

      let batch = |n| {
        serai_mock_rpc::events::in_instructions::batch(
          network,
          session,
          n,
          serai_primitives::BlockHash(block_hash),
          [0u8; 32],
          empty_bitvec.clone(),
        )
      };

      let (hash0, events0, _) = mock_serai.add_block_with_events(vec![vec![batch(id)]]).await;
      let (hash1, events1, _) = mock_serai.add_block_with_events(vec![vec![batch(id)]]).await;
      let mut txn = task_test.db.txn();
      seed_cosigned_blocks(&mut txn, &[(0, hash0), (1, hash1)], &[events0, events1]);
      txn.commit();

      let result = std::panic::AssertUnwindSafe(async {
        let mut task = task_test.task();
        TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
      })
      .catch_unwind()
      .await;

      let err = result.expect_err("should panic on non-increment batch ID");
      assert!(panic_message(&err).contains("not an increment of the last indexed batch's ID"));
    }

    // Case 2: Two batches with IDs that are not sequential (skip a number)
    {
      let (mock_serai, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
      let network = random_external_network_id(&mut OsRng);
      let session = serai_abi::primitives::validator_sets::Session(OsRng.next_u32());
      let block_hash = [0u8; 32];

      let batch = |n| {
        serai_mock_rpc::events::in_instructions::batch(
          network,
          session,
          n,
          serai_primitives::BlockHash(block_hash),
          [0u8; 32],
          empty_bitvec.clone(),
        )
      };

      let (hash0, events0, _) = mock_serai.add_block_with_events(vec![vec![batch(10)]]).await;
      let (hash1, events1, _) = mock_serai.add_block_with_events(vec![vec![batch(20)]]).await;
      let mut txn = task_test.db.txn();
      seed_cosigned_blocks(&mut txn, &[(0, hash0), (1, hash1)], &[events0, events1]);
      txn.commit();

      let result = std::panic::AssertUnwindSafe(async {
        let mut task = task_test.task();
        TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
      })
      .catch_unwind()
      .await;

      let err = result.expect_err("should panic on non-increment batch ID");
      assert!(panic_message(&err).contains("not an increment of the last indexed batch's ID"));
    }

    // Case 3: Second batch has a lower ID than the first (non-increment)
    {
      let (mock_serai, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
      let network = random_external_network_id(&mut OsRng);
      let session = serai_abi::primitives::validator_sets::Session(OsRng.next_u32());
      let block_hash = [0u8; 32];

      let batch = |n| {
        serai_mock_rpc::events::in_instructions::batch(
          network,
          session,
          n,
          serai_primitives::BlockHash(block_hash),
          [0u8; 32],
          empty_bitvec.clone(),
        )
      };

      let (hash0, events0, _) = mock_serai.add_block_with_events(vec![vec![batch(5)]]).await;
      let (hash1, events1, _) = mock_serai.add_block_with_events(vec![vec![batch(3)]]).await;
      let mut txn = task_test.db.txn();
      seed_cosigned_blocks(&mut txn, &[(0, hash0), (1, hash1)], &[events0, events1]);
      txn.commit();

      let result = std::panic::AssertUnwindSafe(async {
        let mut task = task_test.task();
        TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
      })
      .catch_unwind()
      .await;

      let err = result.expect_err("should panic on non-increment batch ID");
      assert!(panic_message(&err).contains("not an increment of the last indexed batch's ID"));
    }
  }
}

#[tokio::test]
async fn processes_cosigned_blocks() {
  // Does not progress on empty cosign DB
  {
    let (_, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
    let mut task = task_test.task();
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
    }
    verify_db_invariants_for_network_and_events(&mut task_test.db, None, &[], &[]);
  }

  // Returns made_progress = true with one or more cosigned blocks
  // Use blocks with no events to avoid SetDecided/SetKeys triggering SlashesReported shims
  // that the verify function doesn't account for.
  {
    let (mock_serai, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
    let (hash, events, block) = mock_serai.add_block_with_events(vec![]).await;
    let block_hashes = [(0u64, hash)];
    let all_events = [events.clone()];
    let all_blocks = [block.clone()];
    {
      let mut txn = task_test.db.txn();
      seed_cosigned_blocks(&mut txn, &block_hashes, &all_events);
      txn.commit();
    }
    let mut task = task_test.task();
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    verify_db_invariants_for_network_and_events(&mut task_test.db, None, &all_events, &all_blocks);
  }

  {
    let (mock_serai, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
    let total_blocks = 10;
    let mut block_hashes = Vec::with_capacity(total_blocks);
    let mut all_events = Vec::with_capacity(total_blocks);
    let mut all_blocks = Vec::with_capacity(total_blocks);
    for i in 0 .. total_blocks {
      let (hash, events, block) = mock_serai.add_block_with_events(vec![]).await;
      block_hashes.push((u64::try_from(i).unwrap(), hash));
      all_events.push(events);
      all_blocks.push(block);
    }
    {
      let mut txn = task_test.db.txn();
      seed_cosigned_blocks(&mut txn, &block_hashes, &all_events);
      txn.commit();
    }
    let mut task = task_test.task();
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
    verify_db_invariants_for_network_and_events(&mut task_test.db, None, &all_events, &all_blocks);

    // Blocks 0..10 were just seeded and indexed by the canonical task.
    // Attempting to seed a previous block does not regress its state
    let block_hash = mock_serai.add_block_with_events(vec![]).await.0;
    {
      let mut txn = task_test.db.txn();
      seed_cosigned_blocks(&mut txn, &[(1u64, block_hash)], &[]);
      txn.commit();
    }
    let mut task = task_test.task();
    {
      // Does not progress on a block previous than the latest
      TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
    }
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      None,
      // Old latest amount of blocks of 10 is still the total_blocks
      &all_events,
      &all_blocks,
    );
  }
}

#[tokio::test]
async fn fuzzed_event_processing() {
  let num_blocks = 1000;

  serai_env::log::info!("Canonical fuzz test: {num_blocks} blocks");

  let (mock_serai, mut task_test) = CanonicalTestStruct::setup_mock_test().await;
  let (block_hashes, all_events, _all_blocks) =
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), num_blocks).await;
  let mut txn = task_test.db.txn();
  seed_cosigned_blocks(&mut txn, &block_hashes, &all_events);
  txn.commit();

  let mut task = task_test.task();
  {
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
  }
}
