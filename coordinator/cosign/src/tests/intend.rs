use std::{
  collections::{HashMap, HashSet},
  fmt::Write as _,
  time::Duration,
};

use core::future::Future;

use blake2::{Digest, Blake2b256};
use k256::{ecdsa::SigningKey as Secp256k1SigningKey, elliptic_curve::sec1::ToEncodedPoint};
use rand_core::{OsRng, RngCore};
use schnorrkel::Keypair as Sr25519Keypair;

use serai_db::{DbTxn, Db as _};
use serai_task::ContinuallyRan;

use serai_client_serai::abi::{
  primitives::{
    BlockHash,
    address::{SeraiAddress, ExternalAddress},
    balance::{Amount, ExternalBalance},
    coin::ExternalCoin,
    crypto::{Public, ExternalKey, KeyPair},
    instructions::{OutInstruction, OutInstructionWithBalance},
    network_id::{ExternalNetworkId, NetworkId},
    validator_sets::{Session, ValidatorSet, ExternalValidatorSet, KeyShares},
  },
  coins, system, validator_sets, Event,
};

use crate::{
  intend::{
    BlockEventData, BlockEvents, CosignIntendTask, GlobalSessionsChannel, IntendedCosigns,
    ScanCosignFrom,
  },
  SeraiRpc,
  tests::*,
  CosignIntent, GlobalSession, GlobalSessions, GlobalSessionsLastBlock, HasEvents,
  LatestGlobalSessionIntended, SubstrateBlockHash,
};
use serai_substrate_tests::{composition, rpc};

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

fn assert_global_session(actual: &GlobalSession, expected: &GlobalSession) {
  assert_eq!(actual.start_block_number, expected.start_block_number);
  assert_eq!(actual.sets, expected.sets);
  assert_eq!(actual.keys, expected.keys);
  assert_eq!(actual.stakes, expected.stakes);
  assert_eq!(actual.total_stake, expected.total_stake);
}

#[tokio::test]
async fn intend_returns_false_with_no_blocks() {
  init_logger();

  let mut env = TestEnvironment::new();

  let mut task = env.into_task();
  assert_eq!(task.run_iteration().await.unwrap(), false);
}

#[tokio::test]
async fn intend_returns_true_with_linear_blocks() {
  init_logger();

  let mut env = TestEnvironment::new();

  let block1_hash = env.serai.make_block(1);
  env.serai.new_events(block1_hash);

  let mut task = env.into_task();
  // Returns true with one block
  assert_eq!(task.run_iteration().await.unwrap(), true);

  let block2_hash = env.serai.make_block(2);
  env.serai.new_events(block2_hash);

  let block3_hash = env.serai.make_block(3);
  env.serai.new_events(block3_hash);

  let mut task = env.into_task();
  // Returns true with sequence of blocks
  assert_eq!(task.run_iteration().await.unwrap(), true);
}

#[tokio::test]
async fn intend_errors_if_chain_is_not_linear() {
  init_logger();

  let mut env = TestEnvironment::new();

  let block1_hash = env.serai.make_block(1);
  env.serai.new_events(block1_hash);

  // Block #2 does not build upon block #1
  env.serai.builds_upon = IncrementalUnbalancedMerkleTree::new();

  let block2_hash = env.serai.make_block(2);
  env.serai.new_events(block2_hash);

  let mut task = env.into_task();
  let err = task.run_iteration().await.unwrap_err();
  assert!(err.contains("doesn't build upon"), "{err}");
}

#[tokio::test]
async fn intend_errors_if_block_not_found() {
  init_logger();

  let mut env = TestEnvironment::new();

  // Make block 1 exist in terms of finalization, but return None when fetched
  let _block1_hash = env.serai.make_block(1);
  env.serai.set_block_not_found(1);

  let mut task = env.into_task();
  let err = task.run_iteration().await.unwrap_err();
  assert!(
    err.contains("couldn't get block which should've been finalized"),
    "unexpected error: {err}"
  );
}

#[tokio::test]
async fn intend_handles_blocks_with_no_events() {
  init_logger();

  let mut env = TestEnvironment::new();

  let block1_hash = env.serai.make_block(1);
  env.serai.new_events(block1_hash);

  let mut task = env.into_task();

  task.run_iteration().await;

  let mut txn = env.db.txn();

  let block = BlockEvents::try_recv(&mut txn).unwrap();
  assert_eq!(block.block_number, 1);
  assert!(matches!(block.has_events, HasEvents::No));

  txn.commit();
}

#[tokio::test]
async fn intend_errors_if_notable_block_has_no_stake() {
  init_logger();

  let mut env = TestEnvironment::new();

  let validator = SeraiAddress([7u8; 32]);

  let block1_hash = env.serai.make_block(1);

  let set0 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
  let vset0 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(0) };

  env
    .serai
    .set_events(block1_hash, vec![set_decided_event(vset0, validator), set_keys_event(set0, 1)]);

  let mut task = env.into_task();
  let err = task.run_iteration().await.unwrap_err();
  assert!(err.contains("had 0 stake"), "{err}");
}

#[tokio::test]
async fn intend_task_indexes_blocks_and_emits_events_and_intents() {
  init_logger();

  let mut env = TestEnvironment::new();

  let validator = SeraiAddress([7u8; 32]);

  let set0 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
  let set1 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(1) };

  let vset0 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(0) };
  let vset1 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(1) };

  let block1_hash = env.serai.make_block(1);
  env.serai.set_events(
    block1_hash,
    vec![
      allocation_event(validator, NetworkId::External(ExternalNetworkId::Bitcoin), 10),
      set_decided_event(vset0, validator),
      set_keys_event(set0, 1),
    ],
  );

  let block2_hash = env.serai.make_block(2);
  env
    .serai
    .set_events(block2_hash, vec![set_decided_event(vset1, validator), set_keys_event(set1, 2)]);

  let mut task = env.into_task();
  assert_eq!(task.run_iteration().await.unwrap(), true);

  assert_eq!(ScanCosignFrom::get(&env.db), Some(3u64));

  let mut txn = env.db.txn();

  // BlockEvents: block 1 is notable but has no prior global session, so it's treated as `No`.

  let first = BlockEvents::try_recv(&mut txn).expect("expected block 1 event");
  assert_eq!(first.block_number, 1);
  assert!(matches!(first.has_events, HasEvents::No));

  let second = BlockEvents::try_recv(&mut txn).expect("expected block 2 event");
  assert_eq!(second.block_number, 2);
  assert!(matches!(second.has_events, HasEvents::Notable));

  assert!(BlockEvents::try_recv(&mut txn).is_none());

  // Global sessions were created at both notable blocks.
  let (session1_id, session1) = {
    let first = GlobalSessionsChannel::try_recv(&mut txn).expect("expected first global session");
    first
  };
  assert_eq!(session1.start_block_number, 2);
  assert_eq!(session1.sets, vec![set0]);

  let (session2_id, session2) = {
    let second = GlobalSessionsChannel::try_recv(&mut txn).expect("expected second global session");
    second
  };
  assert_ne!(session1_id, session2_id);
  assert_eq!(session2.start_block_number, 3);
  assert_eq!(session2.sets, vec![set1]);

  // Block 2 should be intended for cosigning by the prior global session.

  let intent = IntendedCosigns::try_recv(&mut txn, set0).expect("expected cosign intent for set0");

  assert_eq!(intent.global_session, session1_id);
  assert_eq!(intent.block_number, 2);
  assert_eq!(intent.block_hash, block2_hash);
  assert!(intent.notable);

  // No additional intents should exist.

  assert!(IntendedCosigns::try_recv(&mut txn, set0).is_none());

  txn.commit();
}

#[tokio::test]
async fn intend_emits_non_notable_for_burn_with_instruction() {
  init_logger();

  let mut env = TestEnvironment::new();

  let validator = SeraiAddress([7u8; 32]);

  let set0 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
  let vset0 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(0) };

  let block1_hash = env.serai.make_block(1);
  env.serai.set_events(
    block1_hash,
    vec![
      allocation_event(validator, NetworkId::External(ExternalNetworkId::Bitcoin), 10),
      set_decided_event(vset0, validator),
      set_keys_event(set0, 1),
    ],
  );

  let block2_hash = env.serai.make_block(2);
  env.serai.set_events(block2_hash, vec![burn_with_instruction_event(validator)]);

  let mut task = env.into_task();
  assert_eq!(task.run_iteration().await.unwrap(), true);

  let mut txn = env.db.txn();
  let _b1 = BlockEvents::try_recv(&mut txn).unwrap();
  let b2 = BlockEvents::try_recv(&mut txn).unwrap();
  assert_eq!(b2.block_number, 2);
  assert!(matches!(b2.has_events, HasEvents::NonNotable));
  txn.commit();
}

#[tokio::test]
async fn intend_updates_stakes_and_ignores_non_external_network_events() {
  init_logger();

  let mut env = TestEnvironment::new();

  let validator = SeraiAddress([7u8; 32]);

  let block1_hash = env.serai.make_block(1);

  let set0 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
  let vset0 =
    ValidatorSet { network: NetworkId::External(ExternalNetworkId::Bitcoin), session: Session(0) };
  let vset_serai = ValidatorSet { network: NetworkId::Serai, session: Session(9) };

  env.serai.set_events(
    block1_hash,
    vec![
      // Non-ValidatorSets event to exercise the `continue` branch in stake processing.
      Event::System(system::Event::TransactionSuccess),
      // Stakes for the external network.
      allocation_event(validator, NetworkId::External(ExternalNetworkId::Bitcoin), 10),
      deallocation_event(validator, NetworkId::External(ExternalNetworkId::Bitcoin), 3),
      // These are ignored as they're not external networks.
      allocation_event(validator, NetworkId::Serai, 999),
      deallocation_event(validator, NetworkId::Serai, 999),
      // Decide the external set.
      set_decided_event(vset0, validator),
      // This SetDecided can't be converted to an external set and is ignored.
      Event::ValidatorSets(validator_sets::Event::AcceptedHandover { set: vset_serai }),
      Event::ValidatorSets(validator_sets::Event::SetDecided {
        set: vset_serai,
        validators: vec![],
      }),
      // Set keys for the external set.
      set_keys_event(set0, 1),
    ],
  );

  let mut task = env.into_task();
  assert_eq!(task.run_iteration().await.unwrap(), true);

  let (_id, info) = {
    let mut txn = env.db.txn();
    let res = GlobalSessionsChannel::try_recv(&mut txn).expect("expected a global session");
    txn.commit();
    res
  };
  assert_eq!(info.start_block_number, 2);
  assert_eq!(info.stakes.get(&ExternalNetworkId::Bitcoin), Some(&7));
  assert_eq!(info.total_stake, 7);
}

fn random_serai_address(rng: &mut OsRng) -> SeraiAddress {
  SeraiAddress(Sr25519Keypair::generate_with(&mut *rng).public.to_bytes())
}

fn random_crypto_key_pair(rng: &mut OsRng) -> KeyPair {
  let substrate_public = Sr25519Keypair::generate_with(&mut *rng).public.to_bytes();
  let external_point =
    Secp256k1SigningKey::random(&mut *rng).verifying_key().to_encoded_point(true);
  let external_key =
    ExternalKey(external_point.as_bytes().to_vec().try_into().expect("compressed key fits"));
  KeyPair(Public(substrate_public), external_key)
}

#[tokio::test]
async fn intend_fuzz_test() {
  init_logger();

  let mut rng = &mut OsRng;

  for iteration in 0..3 {
    let network = ExternalNetworkId::Bitcoin;
    let validators: Vec<SeraiAddress> = (0..3).map(|_| random_serai_address(rng)).collect();

    let mut serai = Serai::default();

    let mut stake_tracker: HashMap<SeraiAddress, u64> = HashMap::new();
    let mut next_session: u32 = 0;
    let mut stakes: HashMap<(ExternalNetworkId, SeraiAddress), u64> = HashMap::new();
    let mut decided_validators: HashMap<ExternalValidatorSet, Vec<SeraiAddress>> = HashMap::new();
    let mut latest_set: HashMap<ExternalNetworkId, (Session, Public, u64)> = HashMap::new();

    let mut expected_block_events = vec![];
    let mut expected_sessions: Vec<([u8; 32], GlobalSession)> = vec![];
    let mut expected_session_last_block: HashMap<[u8; 32], u64> = HashMap::new();
    let mut expected_latest_global_session: Option<[u8; 32]> = None;
    let mut expected_intents: HashMap<ExternalValidatorSet, Vec<CosignIntent>> = HashMap::new();

    let block_count = 8 + (rng.next_u32() % 5) as u64;
    let forced_new_session_block = block_count / 2;
    let forced_burn_after_new_session_block = forced_new_session_block + 1;

    for block_number in 1..=block_count {
      let mut planned_stakes = stake_tracker.clone();
      let mut tx_events = vec![];

      let adjustments = usize::try_from(rng.next_u32() % 3).unwrap_or(0);
      for _ in 0..adjustments {
        let should_allocate =
          (rng.next_u32() % 2 == 0) || planned_stakes.values().all(|stake| *stake == 0);

        if should_allocate {
          let validator = validators[(rng.next_u32() as usize) % validators.len()];
          let amount = (rng.next_u64() % 10) + 1;
          *planned_stakes.entry(validator).or_default() += amount;

          tx_events.push(allocation_event(validator, NetworkId::External(network), amount));
        } else {
          let available: Vec<_> = validators
            .iter()
            .copied()
            .filter(|validator| planned_stakes.get(validator).copied().unwrap_or(0) > 0)
            .collect();
          if let Some(validator) = available.get((rng.next_u32() as usize) % available.len()) {
            let validator = *validator;
            let current = planned_stakes[&validator];
            let amount = (rng.next_u64() % current).saturating_add(1);
            planned_stakes.insert(validator, current - amount);

            tx_events.push(deallocation_event(validator, NetworkId::External(network), amount));
          }
        }
      }

      let include_burn = block_number != 1
        && ((block_number == 2)
          || (block_number == forced_burn_after_new_session_block)
          || (rng.next_u32() % 3 == 0));

      let is_initial_session = block_number == 1; // Session 0
      let is_random_session = (block_number > 2 && (rng.next_u32() % 10 == 0)); // 10% chance
      let will_create_new_session =
        (block_number == forced_new_session_block) || is_initial_session || is_random_session;

      if will_create_new_session {
        let validator = {
          let mut available = validators
            .iter()
            .copied()
            .filter(|validator| planned_stakes.get(validator).copied().unwrap_or(0) > 0)
            .collect::<Vec<_>>();

          if available.is_empty() {
            let validator = validators[(rng.next_u32() as usize) % validators.len()];
            let top_up = (rng.next_u64() % 10) + 1;

            *planned_stakes.entry(validator).or_default() += top_up;

            tx_events.push(allocation_event(validator, NetworkId::External(network), top_up));
            validator
          } else {
            available[(rng.next_u32() as usize) % available.len()]
          }
        };

        let session = Session(next_session.try_into().unwrap());
        let set = ExternalValidatorSet { network, session };
        let vset = ValidatorSet { network: NetworkId::External(network), session };

        tx_events.push(set_decided_event(vset, validator));
        let key_pair = random_crypto_key_pair(rng);

        tx_events.push(set_keys_event_with_pair(set, &key_pair));
        next_session = next_session.saturating_add(1);
      }

      if include_burn {
        let burn_from = validators[(rng.next_u32() as usize) % validators.len()];

        tx_events.push(burn_with_instruction_event(burn_from));
      }

      let block_hash = serai.make_block(block_number);

      serai.set_events(block_hash, tx_events.clone());

      let mut has_set_keys = false;
      let mut has_burn = false;

      for event in tx_events {
        match event {
          Event::ValidatorSets(validator_sets::Event::Allocation {
            validator,
            network,
            amount,
          }) => {
            let Ok(network) = ExternalNetworkId::try_from(network) else { continue };
            let key = (network, validator);
            *stakes.entry(key).or_default() += amount.0;
          }
          Event::ValidatorSets(validator_sets::Event::Deallocation {
            validator,
            network,
            amount,
            timeline: _,
          }) => {
            let Ok(network) = ExternalNetworkId::try_from(network) else { continue };
            let key = (network, validator);
            let stake = stakes.get_mut(&key).expect("deallocating missing stake");
            assert!(*stake >= amount.0, "deallocation underflow in expected model");
            *stake -= amount.0;
          }
          Event::ValidatorSets(validator_sets::Event::SetDecided {
            set,
            validators: event_validators,
          }) => {
            let Ok(set) = ExternalValidatorSet::try_from(set) else { continue };
            decided_validators
              .insert(set, event_validators.iter().map(|(validator, _)| *validator).collect());
          }
          Event::ValidatorSets(validator_sets::Event::SetKeys { set, key_pair }) => {
            has_set_keys = true;
            let validators =
              decided_validators.remove(&set).expect("set which wasn't decided set keys");
            let mut total_stake = 0;
            for validator in validators {
              total_stake += stakes.get(&(set.network, validator)).copied().unwrap_or(0);
            }
            latest_set.insert(set.network, (set.session, key_pair.0, total_stake));
          }
          Event::Coins(coins::Event::BurnWithInstruction { .. }) => has_burn = true,
          _ => {}
        }
      }

      let mut has_events = if has_set_keys {
        HasEvents::Notable
      } else if has_burn {
        HasEvents::NonNotable
      } else {
        HasEvents::No
      };

      let global_session_for_this_block = expected_latest_global_session;

      if has_events == HasEvents::Notable {
        let mut sets = vec![];
        let mut keys = HashMap::new();
        let mut session_stakes = HashMap::new();
        let mut total_stake = 0;

        for network in ExternalNetworkId::all() {
          if let Some((session, key, stake)) = latest_set.get(&network).copied() {
            let set = ExternalValidatorSet { network, session };
            sets.push(set);
            keys.insert(network, key);
            session_stakes.insert(network, stake);
            total_stake += stake;
          }
        }

        assert!(total_stake > 0, "cosigning sets for block #{block_number} had 0 stake in total");

        let global_session = GlobalSession {
          start_block_number: block_number + 1,
          sets: sets.clone(),
          keys,
          stakes: session_stakes,
          total_stake,
        };
        let session_id = GlobalSession::id(sets);
        if let Some(existing) = global_session_for_this_block {
          expected_session_last_block.insert(existing, block_number);
        }
        expected_latest_global_session = Some(session_id);
        expected_sessions.push((session_id, global_session));
      }

      if global_session_for_this_block.is_none() {
        has_events = HasEvents::No;
      }

      if matches!(has_events, HasEvents::Notable | HasEvents::NonNotable) {
        if let Some(global_session) = global_session_for_this_block {
          let session = expected_sessions
            .iter()
            .find(|(session_id, _)| *session_id == global_session)
            .map(|(_, session)| session)
            .expect("global session missing from expected state");
          for set in &session.sets {
            let intent = CosignIntent {
              global_session,
              block_number,
              block_hash,
              notable: has_events == HasEvents::Notable,
            };
            expected_intents.entry(*set).or_default().push(intent);
          }
        }
      }

      expected_block_events.push(BlockEventData { block_number, has_events });

      stake_tracker = planned_stakes;
    }

    let blocks_by_number = serai.blocks_by_number.clone();

    let mut env = TestEnvironment::from_serai(serai);

    let mut task = env.into_task();

    task.run_iteration().await.unwrap();

    let latest_block = block_count;

    let scan_cosign_from = ScanCosignFrom::get(&env.db);
    assert_eq!(scan_cosign_from, Some(latest_block + 1));

    let mut txn = env.db.txn();

    let mut block_events = vec![];
    while let Some(event) = BlockEvents::try_recv(&mut txn) {
      block_events.push(event);
    }

    assert_eq!(block_events.len(), expected_block_events.len());

    for (idx, (actual, expected)) in block_events.iter().zip(&expected_block_events).enumerate() {
      assert_eq!(actual.block_number, expected.block_number);
      assert_eq!(actual.has_events, expected.has_events);
    }

    for (block_number, block) in &blocks_by_number {
      let stored_hash = SubstrateBlockHash::get(&txn, *block_number);
      let expected_hash = Some(block.header.hash());
      assert_eq!(stored_hash, expected_hash);
    }

    let mut sessions_from_channel = vec![];
    while let Some(entry) = GlobalSessionsChannel::try_recv(&mut txn) {
      sessions_from_channel.push(entry);
    }

    assert_eq!(sessions_from_channel.len(), expected_sessions.len());
    for (idx, ((actual_id, actual_session), (expected_id, expected_session))) in
      sessions_from_channel.iter().zip(&expected_sessions).enumerate()
    {
      assert_eq!(actual_id, expected_id);
      assert_global_session(actual_session, expected_session);
    }

    for (session_id, expected_session) in &expected_sessions {
      let stored = GlobalSessions::get(&txn, *session_id).expect("missing stored global session");
      assert_global_session(&stored, expected_session);
      let expected_last_block = expected_session_last_block.get(session_id).copied();
      let stored_last_block = GlobalSessionsLastBlock::get(&txn, *session_id);
      assert_eq!(stored_last_block, expected_last_block);
    }
    let latest_intended = LatestGlobalSessionIntended::get(&txn);
    assert_eq!(latest_intended, expected_latest_global_session);

    let all_sets: HashSet<_> =
      expected_sessions.iter().flat_map(|(_, session)| session.sets.iter().copied()).collect();

    for set in all_sets {
      let mut actual = vec![];
      while let Some(intent) = IntendedCosigns::try_recv(&mut txn, set) {
        actual.push(intent);
      }
      let expected = expected_intents.get(&set).cloned().unwrap_or_default();
      assert_eq!(actual, expected, "intents mismatch for set {:?}", set);
    }

    txn.commit();
  }
}
