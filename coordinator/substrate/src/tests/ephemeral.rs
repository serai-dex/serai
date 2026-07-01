use dalek_ff_group::Ristretto;
use futures::FutureExt as _;
use rand_core::OsRng;
use ciphersuite::{WrappedGroup, group::GroupEncoding as _};
use serai_cosign::test_helpers::random_global_cosigning_session_id;
use serai_primitives::{network_id::NetworkId, validator_sets::ExternalValidatorSet};
use serai_task::{FuturesRangeProcessor as _, test_helpers::IntoMockSerai};

use serai_abi::{Block, Event};
use serai_client_serai::{
  Serai,
  abi::{
    self,
    primitives::{
      network_id::ExternalNetworkId,
      test_helpers::{random_serai_address, random_ristretto_public_key},
      crypto::EmbeddedEllipticCurveKeys as AuxiliaryKeysStruct,
    },
  },
};

use std::collections::HashMap;

use serai_mock_rpc::block_events_fuzzer::BlockEventsFuzzer;
use crate::{
  TributaryValidatorSetInfo,
  ephemeral::{EphemeralEventStream, ScanEphemeralBlocksFrom},
};
use serai_cosign::{Cosigning, AuxiliaryKeys, test_helpers::set_auxiliary_keys};
use super::*;

pub(crate) struct EphemeralTestStruct {
  pub(crate) serai: Arc<Serai>,
  pub(crate) db: MemDb,
  pub(crate) public_serai_auxiliary_key: <Ristretto as WrappedGroup>::G,
}

serai_task::impl_serai_task_test_struct!(EphemeralTestStruct,
    public_serai_auxiliary_key: random_ristretto_public_key(&mut OsRng)
);

impl IntoTask for EphemeralTestStruct {
  type Task = EphemeralEventStream<MemDb>;

  fn task(&self) -> Self::Task {
    EphemeralEventStream::new(self.db.clone(), self.serai.clone(), self.public_serai_auxiliary_key)
  }
}

impl IntoMockSerai for EphemeralTestStruct {}

fn verify_db_invariants_for_network_and_events(
  db: &mut MemDb,
  validator: <Ristretto as WrappedGroup>::G,
  networks: Option<Vec<NetworkId>>,
  events: &[Vec<Event>],
  blocks: &[Block],
) {
  let num_blocks = events.len();
  if num_blocks > 0 {
    // ScanEphemeralBlocksFrom should point to the block after the last processed
    assert_eq!(
      ScanEphemeralBlocksFrom::get(db),
      Some(u64::try_from(num_blocks).unwrap()),
      "ScanEphemeralBlocksFrom should be {num_blocks} after processing blocks 0..={num_blocks}"
    );
  } else {
    assert!(
      ScanEphemeralBlocksFrom::get(db).is_none(),
      "ScanEphemeralBlocksFrom should be None after not processing any blocks",
    );
  }

  let mut txn = db.txn();

  #[expect(clippy::type_complexity)]
  let mut expected_new_sets: HashMap<
    ExternalValidatorSet,
    ([u8; 32], u64, Vec<(([u8; 32], Vec<u8>), u16)>),
  > = HashMap::new();

  for network in networks.unwrap_or_else(|| NetworkId::all().collect()) {
    // Serai has no validator sets or tributaries, skip it
    let Ok(external_network) = ExternalNetworkId::try_from(network) else { continue };

    // For all events in all blocks find the ones for the current network
    for (block_idx, block_events) in events.iter().enumerate() {
      let expected_block_hash = blocks[block_idx].header.hash();
      let expected_serai_time = blocks[block_idx].header.unix_time_in_millis() / 1000;

      let mut embedded_elliptic_curve_keys_events = Vec::new();
      let mut set_decided_events = Vec::new();
      let mut accepted_handover_events = Vec::new();

      for event in block_events {
        if let serai_abi::Event::ValidatorSets(vset_event) = event {
          #[expect(clippy::wildcard_enum_match_arm)]
          match vset_event {
            abi::validator_sets::Event::SetEmbeddedEllipticCurveKeys { keys, .. }
              if keys.network() == external_network.into() =>
            {
              embedded_elliptic_curve_keys_events.push(vset_event);
            }
            abi::validator_sets::Event::SetDecided { set, .. }
              if set.network == external_network.into() =>
            {
              set_decided_events.push(vset_event);
            }
            abi::validator_sets::Event::AcceptedHandover { set }
              if set.network == external_network.into() =>
            {
              accepted_handover_events.push(vset_event);
            }
            _ => {}
          }
        }
      }

      for event in embedded_elliptic_curve_keys_events {
        let serai_client_serai::abi::validator_sets::Event::SetEmbeddedEllipticCurveKeys {
          validator,
          keys,
        } = &event
        else {
          unreachable!(
            "{}: {event:?}",
            "`SetEmbeddedEllipticCurveKeys` event wasn't a `SetEmbeddedEllipticCurveKeys` event"
          );
        };

        // We only coordinate over external networks
        let Ok(_) = ExternalNetworkId::try_from(keys.network()) else { continue };

        let to_raw = |keys: AuxiliaryKeysStruct| match keys {
          AuxiliaryKeysStruct::Serai(s) | AuxiliaryKeysStruct::Monero(s) => (s, s.to_vec()),
          AuxiliaryKeysStruct::Bitcoin(s, e) | AuxiliaryKeysStruct::Ethereum(s, e) => {
            (s, e.to_vec())
          }
        };

        let from_event = to_raw(*keys);
        let db_entry = AuxiliaryKeys::get(&txn, external_network.into(), *validator);
        let from_db = to_raw(db_entry.expect("selected validator lacked auxiliary keys"));
        assert_eq!(from_event, from_db, "auxiliary keys from event and DB don't match");
      }

      for set_decided in set_decided_events {
        let serai_client_serai::abi::validator_sets::Event::SetDecided { set, validators } =
          &set_decided
        else {
          unreachable!("`SetDecided` event wasn't a `SetDecided` event: {set_decided:?}");
        };

        // We only coordinate over external networks
        let Ok(external_set) = ExternalValidatorSet::try_from(*set) else { continue };

        let to_aux_keys = |keys: AuxiliaryKeysStruct| match keys {
          AuxiliaryKeysStruct::Serai(s) | AuxiliaryKeysStruct::Monero(s) => (s, s.to_vec()),
          AuxiliaryKeysStruct::Bitcoin(s, e) | AuxiliaryKeysStruct::Ethereum(s, e) => {
            (s, e.to_vec())
          }
        };

        let expected_validators = validators
          .iter()
          .map(|(validator, weight)| {
            let db_entry = AuxiliaryKeys::get(&txn, external_set.network.into(), *validator);
            (
              to_aux_keys(db_entry.expect("selected validator lacked auxiliary keys")),
              u16::from(*weight),
            )
          })
          .collect::<Vec<_>>();

        // The coordinator only emits EphemeralNewDecidedSet when it is itself in the decided set.
        if validators.iter().any(|(v, _)| {
          let serai_key = serai_cosign::serai_networks_auxiliary_key(&txn, *v);
          serai_key.0 == validator
        }) {
          expected_new_sets.insert(
            external_set,
            (expected_block_hash.0, expected_serai_time, expected_validators),
          );
        }
      }

      for accepted_handover in accepted_handover_events {
        let serai_client_serai::abi::validator_sets::Event::AcceptedHandover { set } =
          &accepted_handover
        else {
          unreachable!(
            "AcceptedHandover event wasn't a AcceptedHandover event: {accepted_handover:?}"
          );
        };

        // We only coordinate over external networks
        let Ok(set) = ExternalValidatorSet::try_from(*set) else { continue };

        let notification_exists = crate::EphemeralSetHasToSignSlashReport::try_recv(&mut txn, set);
        assert!(notification_exists.is_some());
      }
    }
  }

  let mut actual_new_sets: HashMap<ExternalValidatorSet, TributaryValidatorSetInfo> =
    HashMap::new();
  while let Some(msg) = crate::EphemeralNewDecidedSet::try_recv(&mut txn) {
    actual_new_sets.insert(msg.set, msg);
  }

  assert_eq!(
    actual_new_sets.keys().collect::<std::collections::HashSet<_>>(),
    expected_new_sets.keys().collect::<std::collections::HashSet<_>>(),
    "EphemeralNewDecidedSet queue has different sets than expected"
  );

  for (set, (expected_block_hash, expected_serai_time, expected_validators)) in &expected_new_sets {
    let msg = &actual_new_sets[set];
    assert_eq!(msg.set, *set, "EphemeralNewDecidedSet.set mismatch");
    assert_eq!(
      msg.serai_block, *expected_block_hash,
      "EphemeralNewDecidedSet.serai_block mismatch for {set:?}"
    );
    assert_eq!(
      msg.declaration_time, *expected_serai_time,
      "EphemeralNewDecidedSet.declaration_time mismatch for {set:?}"
    );

    let actual_initial = &msg.tributary_validator_set.initial_tributary_validators;
    assert_eq!(
      actual_initial.len(),
      expected_validators.len(),
      "initial_tributary_validators length mismatch for {set:?}"
    );
    for (actual, expected) in actual_initial.iter().zip(expected_validators.iter()) {
      let ((expected_substrate_key, expected_external_key), expected_weight) = expected;
      assert_eq!(actual.networks_substrate_key, *expected_substrate_key);
      assert_eq!(actual.networks_external_key, *expected_external_key);
      assert_eq!(actual.weight, *expected_weight);
    }

    let total_expected_weight: u16 = expected_validators.iter().map(|(_, weight)| weight).sum();
    assert_eq!(
      msg.tributary_validator_set.total_weight(),
      total_expected_weight,
      "total_weight mismatch for {set:?}"
    );
    assert_eq!(
      msg.tributary_validator_set.evrf_networks_substrate_keys().len(),
      usize::from(total_expected_weight),
      "evrf_networks_substrate_keys length mismatch for {set:?}"
    );
    assert_eq!(
      msg.tributary_validator_set.evrf_networks_external_keys().len(),
      usize::from(total_expected_weight),
      "evrf_networks_external_keys length mismatch for {set:?}"
    );
    let mut expected_substrate_keys: Vec<[u8; 32]> =
      Vec::with_capacity(usize::from(total_expected_weight));
    for ((substrate_key, _), weight) in expected_validators {
      for _ in 0 .. *weight {
        expected_substrate_keys.push(*substrate_key);
      }
    }
    assert_eq!(
      msg.tributary_validator_set.evrf_networks_substrate_keys(),
      &expected_substrate_keys,
      "evrf_networks_substrate_keys mismatch for {set:?}"
    );

    let mut expected_external_keys: Vec<Vec<u8>> =
      Vec::with_capacity(usize::from(total_expected_weight));
    for ((_, external_key), weight) in expected_validators {
      for _ in 0 .. *weight {
        expected_external_keys.push(external_key.clone());
      }
    }
    assert_eq!(
      msg.tributary_validator_set.evrf_networks_external_keys(),
      &expected_external_keys,
      "evrf_networks_external_keys mismatch for {set:?}"
    );
  }

  // `txn` is dropped here without `.commit()`. The channel is left unchanged.
  // retries have to iterate over all block/events & message elements again
  // txn.commit();
}

mod errors {
  use super::*;

  #[tokio::test]
  async fn handles_faulted_session() {
    let (mock_serai, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
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
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      task_test.public_serai_auxiliary_key,
      None,
      &[],
      &[],
    );
  }

  #[tokio::test]
  #[should_panic(
    expected = "iterating to latest cosigned block but couldn't get cosigned block number"
  )]
  async fn panics_on_cosigned_block_no_latest_is_none() {
    let (mock_serai, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
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
    let (_, mut task_test) = EphemeralTestStruct::setup_mock_test().await;

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
    let (mock_serai, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
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
    let (mock_serai, mut task_test) = EphemeralTestStruct::setup_mock_test().await;

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
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      task_test.public_serai_auxiliary_key,
      None,
      &[],
      &[],
    );
  }

  #[tokio::test]
  async fn handles_serai_block_rpc_error() {
    let (mock_serai, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
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
      task_test.public_serai_auxiliary_key,
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
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      task_test.public_serai_auxiliary_key,
      None,
      &all_events,
      &all_blocks,
    );
  }

  #[tokio::test]
  async fn panics_on_serai_block_none_from_serai() {
    let (mock_serai, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
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
    let (mock_serai, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
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
      task_test.public_serai_auxiliary_key,
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
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      task_test.public_serai_auxiliary_key,
      None,
      &all_events,
      &all_blocks,
    );
  }

  #[tokio::test]
  async fn rejects_set_decided_with_too_many_validators() {
    use serai_abi::{
      primitives::{
        validator_sets::{KeyShares, Session, ValidatorSet},
      },
    };
    use serai_mock_rpc::events::validator_sets::set_decided;
    use serai_primitives::test_helpers::{
      random_external_network_id, random_embedded_elliptic_curve_keys,
    };

    let (mock_serai, mut task_test) = EphemeralTestStruct::setup_mock_test().await;

    // Pick a random external network and generate matching auxiliary keys.
    let network = random_external_network_id(&mut OsRng);
    let aux_keys = random_embedded_elliptic_curve_keys(&mut OsRng, network.into());

    // Build a SetDecided with u16::MAX + 1 validators, one of which is our validator.
    // This exercises the `more than u16::MAX validators sent` error path, which fires
    // before any AuxiliaryKeys lookup - so no SetEmbeddedEllipticCurveKeys events needed.
    let num_validators = usize::from(u16::MAX) + 1;
    let validators: Vec<(serai_primitives::address::SeraiAddress, KeyShares)> =
      (0 .. num_validators).map(|_| (random_serai_address(&mut OsRng), KeyShares::ONE)).collect();

    // Ensure our coordinator's validator is in the set.
    {
      let mut txn = task_test.db.txn();
      set_auxiliary_keys(&mut txn, network.into(), validators[0].0, &aux_keys);
      txn.commit();
    }

    let event =
      set_decided(ValidatorSet { network: network.into(), session: Session(0) }, validators);

    let (hash, _, _) = mock_serai.add_block_with_events(vec![vec![event]]).await;
    let mut txn = task_test.db.txn();
    seed_cosigned_blocks(&mut txn, &[(0, hash)], &[]);
    txn.commit();

    let mut task = task_test.task();
    TaskTest::task_runs_and_panics_with(&mut task, "more than u16::MAX validators sent").await;
  }

  #[tokio::test]
  async fn rejects_set_decided_exceeding_max_key_shares() {
    use serai_abi::{
      primitives::{
        validator_sets::{KeyShares, Session, ValidatorSet},
      },
    };
    use serai_mock_rpc::events::validator_sets::set_decided;
    use serai_primitives::{
      crypto::EmbeddedEllipticCurveKeys,
      test_helpers::{random_external_network_id, random_embedded_elliptic_curve_keys},
    };

    let (mock_serai, mut task_test) = EphemeralTestStruct::setup_mock_test().await;

    // Pick a random external network and generate matching auxiliary keys.
    let network = random_external_network_id(&mut OsRng);

    // Two validators each with weight 64 gives total_weight = 128 > MAX_PER_SET (127).
    // Our validator is one of them, so `are_we_in_set = true` and the weight check fires.
    let over_weight = KeyShares::saturating_from(64);
    let validators = vec![
      (random_serai_address(&mut OsRng), over_weight),
      (random_serai_address(&mut OsRng), over_weight),
    ];

    // Store auxiliary keys for ALL validators, the task looks up every validator's
    // auxiliary key before checking whether we are in the set.
    {
      let mut txn = task_test.db.txn();
      let our_key_bytes = task_test.public_serai_auxiliary_key.to_bytes();

      for (i, (validator, _)) in validators.iter().enumerate() {
        let keys = if i == 0 {
          // Our validator: substrate key starts with our public key's first byte
          let mut substrate = random_embedded_elliptic_curve_keys(&mut OsRng, network.into());
          match &mut substrate {
            EmbeddedEllipticCurveKeys::Bitcoin(s, _) |
            EmbeddedEllipticCurveKeys::Ethereum(s, _) |
            EmbeddedEllipticCurveKeys::Monero(s) => s[0] = our_key_bytes[0],
            EmbeddedEllipticCurveKeys::Serai(_) => unreachable!("external network"),
          }
          substrate
        } else {
          random_embedded_elliptic_curve_keys(&mut OsRng, network.into())
        };
        set_auxiliary_keys(&mut txn, network.into(), *validator, &keys);

        // Store the auxiliary key on NetworkId::Serai.
        let serai_key = if i == 0 {
          EmbeddedEllipticCurveKeys::Serai(our_key_bytes)
        } else {
          random_embedded_elliptic_curve_keys(&mut OsRng, NetworkId::Serai)
        };
        set_auxiliary_keys(&mut txn, NetworkId::Serai, *validator, &serai_key);
      }
      txn.commit();
    }

    let event =
      set_decided(ValidatorSet { network: network.into(), session: Session(0) }, validators);

    let (hash, _events, _) = mock_serai.add_block_with_events(vec![vec![event]]).await;
    let mut txn = task_test.db.txn();
    seed_cosigned_blocks(&mut txn, &[(0, hash)], &[]);
    txn.commit();

    let mut task = task_test.task();
    TaskTest::task_runs_and_panics_with(
      &mut task,
      &format!("key shares when the max is {}", KeyShares::MAX_PER_SET),
    )
    .await;
  }
}

mod progresses {
  use super::*;

  #[tokio::test]
  async fn processes_cosigned_blocks() {
    // Does not progress on empty cosign DB
    {
      let (_, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
      let mut task = task_test.task();
      {
        TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
      }
      verify_db_invariants_for_network_and_events(
        &mut task_test.db,
        task_test.public_serai_auxiliary_key,
        None,
        &[],
        &[],
      );
    }

    // Returns made_progress = true with one or more cosigned blocks
    {
      let (mock_serai, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
      let (block_hashes, all_events, all_blocks) =
        mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;
      let mut txn = task_test.db.txn();
      seed_cosigned_blocks(&mut txn, &block_hashes, &all_events);
      txn.commit();
      let mut task = task_test.task();
      {
        TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
      }
      verify_db_invariants_for_network_and_events(
        &mut task_test.db,
        task_test.public_serai_auxiliary_key,
        None,
        &all_events,
        &all_blocks,
      );
    }

    {
      let (mock_serai, mut task_test) = EphemeralTestStruct::setup_mock_test().await;
      let total_blocks = 10;
      let (block_hashes, all_events, all_blocks) =
        mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), total_blocks).await;
      let mut txn = task_test.db.txn();
      seed_cosigned_blocks(&mut txn, &block_hashes, &all_events);
      txn.commit();
      let mut task = task_test.task();
      {
        TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
      }
      verify_db_invariants_for_network_and_events(
        &mut task_test.db,
        task_test.public_serai_auxiliary_key,
        None,
        &all_events,
        &all_blocks,
      );

      // Blocks 0..10 were just seeded and indexed by the canonical task.
      // Attempting to seed a previous block does not regress its state
      let block_hash = mock_serai.add_block_with_events(vec![]).await.0;
      let mut txn = task_test.db.txn();
      seed_cosigned_blocks(&mut txn, &[(1u64, block_hash)], &[]);
      txn.commit();
      let mut task = task_test.task();
      {
        // Does not progress on a block previous than the latest
        TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
      }
      verify_db_invariants_for_network_and_events(
        &mut task_test.db,
        task_test.public_serai_auxiliary_key,
        None,
        // Old latest amount of blocks of 10 is still the total_blocks
        &all_events,
        &all_blocks,
      );
    }
  }

  #[tokio::test]
  async fn processes_our_validator() {
    use serai_abi::{
      primitives::{
        network_id::{NetworkId, ExternalNetworkId},
        validator_sets::{KeyShares, Session, ValidatorSet},
      },
      validator_sets::Event as ValidatorSetsEvent,
    };
    use serai_mock_rpc::events::validator_sets::set_decided;

    let (mock_serai, mut task_test) = EphemeralTestStruct::setup_mock_test().await;

    let our_auxiliary_key = task_test.public_serai_auxiliary_key;
    let our_identity = random_serai_address(&mut OsRng);

    // Emit SetEmbeddedEllipticCurveKeys for our validator on NetworkId::Serai
    // This is required so that serai_networks_auxiliary_key() can find it.
    let serai_embedded_keys_event =
      Event::ValidatorSets(ValidatorSetsEvent::SetEmbeddedEllipticCurveKeys {
        validator: our_identity,
        keys: AuxiliaryKeysStruct::Serai(our_auxiliary_key.to_bytes()),
      });
    // Also emit on Monero (external network) for the Batch/SetDecided events
    let monero_embedded_keys_event =
      Event::ValidatorSets(ValidatorSetsEvent::SetEmbeddedEllipticCurveKeys {
        validator: our_identity,
        keys: AuxiliaryKeysStruct::Monero(our_auxiliary_key.to_bytes()),
      });
    let (hash0, events0, block0) = mock_serai
      .add_block_with_events(vec![vec![
        serai_embedded_keys_event.clone(),
        monero_embedded_keys_event.clone(),
      ]])
      .await;
    {
      let mut txn = task_test.db.txn();
      seed_cosigned_blocks(&mut txn, &[(0, hash0)], &[events0]);
      txn.commit();
    }

    // Run the task to process the block, storing our auxiliary key in the DB
    let mut task = task_test.task();
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }

    // Verify our auxiliary key was stored in the DB for our validator identity
    {
      let txn = task_test.db.txn();
      let stored_key = AuxiliaryKeys::get(&txn, ExternalNetworkId::Monero.into(), our_identity);
      assert!(
        stored_key.is_some(),
        "our auxiliary key should be stored in DB after processing SetEmbeddedEllipticCurveKeys"
      );
      let AuxiliaryKeysStruct::Monero(stored_bytes) = stored_key.unwrap() else {
        panic!("expected Serai auxiliary keys struct");
      };
      assert_eq!(
        stored_bytes.as_ref(),
        our_auxiliary_key.to_bytes().as_ref(),
        "stored auxiliary key should match our public_serai_auxiliary_key"
      );
    }

    // Second block: emit SetDecided with our validator in the set
    // Since our auxiliary key is now in the DB (via the Serai SetEmbeddedEllipticCurveKeys event),
    // are_we_in_set will return true and the coordinator will process this set
    //
    // We need to emit SetEmbeddedEllipticCurveKeys for all validators on the external network
    // before emitting SetDecided, as the coordinator will try to fetch their keys from that network
    use serai_primitives::test_helpers::random_embedded_elliptic_curve_keys;

    let validators = vec![(our_identity, KeyShares::ONE)];

    // Emit SetEmbeddedEllipticCurveKeys for our validator on the external network (Bitcoin)
    let external_keys =
      random_embedded_elliptic_curve_keys(&mut OsRng, ExternalNetworkId::Bitcoin.into());
    let external_keys_event =
      Event::ValidatorSets(ValidatorSetsEvent::SetEmbeddedEllipticCurveKeys {
        validator: our_identity,
        keys: external_keys,
      });

    let set_decided = set_decided(
      ValidatorSet {
        network: NetworkId::External(ExternalNetworkId::Bitcoin),
        session: Session(0),
      },
      validators,
    );

    let (hash1, events1, block1) =
      mock_serai.add_block_with_events(vec![vec![external_keys_event, set_decided.clone()]]).await;
    let mut txn = task_test.db.txn();
    seed_cosigned_blocks(&mut txn, &[(1, hash1)], &[events1]);
    txn.commit();

    // Run the task again to process the SetDecided event
    // This should succeed since are_we_in_set returns true (our auxiliary key was set)
    let mut task = task_test.task();
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }

    // Verify both blocks were processed correctly
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      task_test.public_serai_auxiliary_key,
      Some(vec![NetworkId::External(ExternalNetworkId::Bitcoin)]),
      // Two blocks of events
      &[
        vec![serai_embedded_keys_event.clone(), monero_embedded_keys_event.clone()],
        vec![set_decided.clone()],
      ],
      &[block0, block1],
    );
  }

  #[tokio::test]
  async fn sends_new_set_when_weight_within_limit() {
    use serai_abi::{
      primitives::{
        network_id::{NetworkId, ExternalNetworkId},
        validator_sets::{KeyShares, Session, ValidatorSet},
      },
    };
    use serai_mock_rpc::events::validator_sets::set_decided;
    use serai_primitives::{
      crypto::EmbeddedEllipticCurveKeys, test_helpers::random_embedded_elliptic_curve_keys,
    };

    let (mock_serai, mut task_test) = EphemeralTestStruct::setup_mock_test().await;

    let our_auxiliary_key = task_test.public_serai_auxiliary_key;
    let our_identity = random_serai_address(&mut OsRng);

    // Build a SetDecided with our validator in the set.
    // Use total_weight = 3 (well under MAX_PER_SET = 127) to ensure the weight check passes
    let validators = vec![
      (our_identity, KeyShares::ONE),
      (random_serai_address(&mut OsRng), KeyShares::ONE),
      (random_serai_address(&mut OsRng), KeyShares::ONE),
    ];

    // Store auxiliary keys for all validators
    {
      let mut txn = task_test.db.txn();
      let our_key_bytes = our_auxiliary_key.to_bytes();

      for (i, (validator, _)) in validators.iter().enumerate() {
        let keys = if i == 0 {
          // Our validator: substrate key starts with our public key's first byte
          let mut substrate =
            random_embedded_elliptic_curve_keys(&mut OsRng, ExternalNetworkId::Bitcoin.into());
          match &mut substrate {
            EmbeddedEllipticCurveKeys::Bitcoin(s, _) |
            EmbeddedEllipticCurveKeys::Ethereum(s, _) |
            EmbeddedEllipticCurveKeys::Monero(s) => s[0] = our_key_bytes[0],
            EmbeddedEllipticCurveKeys::Serai(_) => unreachable!("external network"),
          }
          substrate
        } else {
          random_embedded_elliptic_curve_keys(&mut OsRng, ExternalNetworkId::Bitcoin.into())
        };
        set_auxiliary_keys(&mut txn, ExternalNetworkId::Bitcoin.into(), *validator, &keys);

        // Also store the auxiliary key on NetworkId::Serai so that
        // serai_networks_auxiliary_key() can find it.
        let serai_key = if i == 0 {
          EmbeddedEllipticCurveKeys::Serai(our_key_bytes)
        } else {
          random_embedded_elliptic_curve_keys(&mut OsRng, NetworkId::Serai)
        };
        set_auxiliary_keys(&mut txn, NetworkId::Serai, *validator, &serai_key);
      }
      txn.commit();
    }

    let set = ValidatorSet {
      network: NetworkId::External(ExternalNetworkId::Bitcoin),
      session: Session(0),
    };
    let set_decided = set_decided(set, validators.clone());

    let (hash, events, block) =
      mock_serai.add_block_with_events(vec![vec![set_decided.clone()]]).await;
    let mut txn = task_test.db.txn();
    seed_cosigned_blocks(&mut txn, &[(0, hash)], &[events]);
    txn.commit();

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    // Verify EphemeralNewDecidedSet was sent
    let mut txn = task_test.db.txn();
    let new_set = crate::EphemeralNewDecidedSet::try_recv(&mut txn).expect(
      "EphemeralNewDecidedSet should have been sent /
        when total_weight <= MAX_PER_SET and we are in set",
    );

    // Verify the NewSetInformation fields are correct
    assert_eq!(new_set.set, ExternalValidatorSet::try_from(set).unwrap());
    assert_eq!(new_set.serai_block, hash.0);
    // Declaration time is block time in seconds
    assert_eq!(new_set.declaration_time, block.header.unix_time_in_millis() / 1000);
    // Verify tributary_validators has the correct number of validators
    assert_eq!(new_set.tributary_validator_set.initial_tributary_validators.len(), 3);
    // Verify participant indexes were initialized
    assert!(!new_set.tributary_validator_set.evrf_networks_external_keys().is_empty());
    assert!(!new_set.tributary_validator_set.evrf_networks_substrate_keys().is_empty());
  }

  #[tokio::test]
  async fn fuzzed_event_processing() {
    let num_blocks = 1000;

    serai_env::log::info!("Canonical fuzz test: {num_blocks} blocks");

    let (mock_serai, mut task_test) = EphemeralTestStruct::setup_mock_test().await;

    // Get our validator address so we can add it to the fuzz blocks
    let our_validator = random_serai_address(&mut OsRng);

    // Also need to set our auxiliary key in the DB for our own validator on NetworkId::Serai
    // This is required for are_we_in_set to return true when our validator is in a SetDecided
    {
      let mut txn = task_test.db.txn();
      set_auxiliary_keys(
        &mut txn,
        NetworkId::Serai,
        our_validator,
        &AuxiliaryKeysStruct::Serai(task_test.public_serai_auxiliary_key.to_bytes()),
      );
      txn.commit();
    }

    // Generate blocks with our validator included in the pool
    // fuzz_blocks_with_validators adds our_validator to the pool so it may be randomly selected
    let (block_hashes, all_events, all_blocks) = mock_serai
      .fuzz_blocks_with_validators(
        &mut BlockEventsFuzzer::new_with_validators(OsRng, 5),
        num_blocks,
      )
      .await;
    let mut txn = task_test.db.txn();
    seed_cosigned_blocks(&mut txn, &block_hashes, &all_events);
    txn.commit();

    let mut task = task_test.task();
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }

    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      task_test.public_serai_auxiliary_key,
      Some(ExternalNetworkId::all().map(NetworkId::from).collect()),
      &all_events,
      &all_blocks,
    );
  }
}
