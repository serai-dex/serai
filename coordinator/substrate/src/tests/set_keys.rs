use rand::{CryptoRng, RngCore};
use rand_core::OsRng;
use serai_primitives::{
  network_id::ExternalNetworkId,
  test_helpers::{random_public, random_external_network_key},
  validator_sets::{ExternalValidatorSet, Session, KeyShares},
  crypto::{KeyPair, Signature, RistrettoSignature},
};
use serai_client_serai::abi::primitives::BitVec;

use serai_mock_rpc::block_events_fuzzer::BlockEventsFuzzer;
use serai_client_serai::Serai;
use serai_task::test_helpers::IntoMockSerai;

use crate::{SetKeysTask, NetworksSetKeysTransaction};
use super::*;

pub(crate) struct SetKeysTestStruct {
  pub(crate) serai: Arc<Serai>,
  pub(crate) db: MemDb,
}

serai_task::impl_serai_task_test_struct!(SetKeysTestStruct);

impl IntoTask for SetKeysTestStruct {
  type Task = SetKeysTask<MemDb>;

  fn task(&self) -> Self::Task {
    SetKeysTask::new(self.db.clone(), self.serai.clone())
  }
}

impl IntoMockSerai for SetKeysTestStruct {}

/// Create a random `KeyPair` for testing.
fn random_key_pair<R: RngCore + CryptoRng>(rng: &mut R) -> KeyPair {
  KeyPair(random_public(rng), random_external_network_key(rng))
}

/// Create a random `RistrettoSignature` for testing.
fn random_ristretto_signature(rng: &mut impl RngCore) -> RistrettoSignature {
  let mut bytes = [0u8; 64];
  rng.fill_bytes(&mut bytes);
  RistrettoSignature(bytes)
}

/// Create a random `BitVec` for signature participants.
#[allow(clippy::cast_possible_truncation, clippy::as_conversions)]
fn random_signature_participants(rng: &mut impl RngCore) -> BitVec<{ KeyShares::MAX_PER_SET_U64 }> {
  // For bound 127, the length prefix is 1 byte.
  // Construct borsh encoding manually: [num_bits (1 byte), packed_bytes...]
  let num_bits = (rng.next_u32() % u32::from(KeyShares::MAX_PER_SET)) as u8;
  let num_bytes = num_bits.div_ceil(8);
  let mut bytes = vec![num_bits];
  for _ in 0 .. num_bytes {
    bytes.push(rng.next_u32() as u8);
  }
  // Clear unused bits in the last byte to ensure canonical encoding
  if num_bits % 8 != 0 {
    let mask = (1u8 << (num_bits % 8)) - 1;
    *bytes.last_mut().unwrap() &= mask;
  }
  borsh::from_slice(&bytes).unwrap()
}

/// Verify DB invariants for keys after the task runs.
fn verify_db_invariants_for_network_and_events(
  db: &mut MemDb,
  networks_with_sessions: &[(ExternalNetworkId, Session)],
  current_sessions: &std::collections::HashMap<ExternalNetworkId, Session>,
) {
  let txn = db.txn();

  for (network, key_session) in networks_with_sessions {
    let current = current_sessions.get(network);
    // Keys are drained when current_session >= key_session (either retired or published)
    let should_be_drained = current.is_some_and(|cs| cs.0 >= key_session.0);
    let exists = crate::_public_db::NetworksSetKeysTransaction::get(&txn, *network);

    if should_be_drained {
      assert!(
        exists.is_none(),
        "network {network:?} with key session {key_session:?} and current session {current:?} \
         should have been drained (current_session >= key_session), but keys still exist"
      );
    } else {
      assert!(
        exists.is_some(),
        "network {network:?} with key session {key_session:?} and current session {current:?} \
         should NOT have been drained (current_session < key_session), but keys are missing"
      );
    }
  }
}

mod errors {
  use super::*;

  #[tokio::test]
  async fn handles_serai_state_rpc_error() {
    let (mock_serai, mut task_test) = SetKeysTestStruct::setup_mock_test().await;
    let (block_hashes, ..) = mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    mock_serai.remove_block(block_hashes.last().unwrap().0).await;

    {
      let mut txn = task_test.db.txn();
      let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
      NetworksSetKeysTransaction::set(
        &mut txn,
        set,
        random_key_pair(&mut OsRng),
        random_signature_participants(&mut OsRng),
        Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
      );
      txn.commit();
    }

    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(&mut task, "InvalidNode").await;
    }
  }

  #[tokio::test]
  async fn handles_serai_current_session_rpc_error() {
    let (mock_serai, mut task_test) = SetKeysTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    mock_serai.set_error("validator-sets/current_session", "timeout").await;

    {
      let mut txn = task_test.db.txn();
      let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
      NetworksSetKeysTransaction::set(
        &mut txn,
        set,
        random_key_pair(&mut OsRng),
        random_signature_participants(&mut OsRng),
        Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
      );
      txn.commit();
    }

    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(&mut task, "ErrorInResponse").await;
    }
  }

  #[tokio::test]
  async fn handles_serai_keys_rpc_error() {
    let (mock_serai, mut task_test) = SetKeysTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    mock_serai.set_error("validator-sets/keys", "timeout").await;

    {
      let mut txn = task_test.db.txn();
      let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
      NetworksSetKeysTransaction::set(
        &mut txn,
        set,
        random_key_pair(&mut OsRng),
        random_signature_participants(&mut OsRng),
        Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
      );
      // Set current session to match the key session so we pass the session check
      mock_serai.set_session(ExternalNetworkId::Bitcoin.into(), Session(0)).await;
      txn.commit();
    }

    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(&mut task, "ErrorInResponse").await;
    }
  }

  #[tokio::test]
  async fn handles_serai_publish_transaction_rpc_error() {
    let (mock_serai, mut task_test) = SetKeysTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    mock_serai.set_error("blockchain/publish_transaction", "timeout").await;

    {
      let mut txn = task_test.db.txn();
      let set = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
      NetworksSetKeysTransaction::set(
        &mut txn,
        set,
        random_key_pair(&mut OsRng),
        random_signature_participants(&mut OsRng),
        Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
      );
      // Set current session to match the key session so we pass the session check
      mock_serai.set_session(ExternalNetworkId::Bitcoin.into(), Session(0)).await;
      txn.commit();
    }

    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(&mut task, "couldn't publish set keys transaction").await;
    }
  }
}

mod progresses {
  use super::*;

  #[tokio::test]
  async fn handles_empty_keys() {
    // No keys in DB = Ok(false)
    let (_, task_test) = SetKeysTestStruct::setup_mock_test().await;
    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
  }

  #[tokio::test]
  async fn publishes_keys_for_current_session() {
    // Keys are for the current session, not yet set on Serai = Ok(true)
    let (mock_serai, mut task_test) = SetKeysTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let network = ExternalNetworkId::Bitcoin;
    let set = ExternalValidatorSet { network, session: Session(0) };
    let key_pair = random_key_pair(&mut OsRng);

    {
      let mut txn = task_test.db.txn();
      NetworksSetKeysTransaction::set(
        &mut txn,
        set,
        key_pair.clone(),
        random_signature_participants(&mut OsRng),
        Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
      );
      // Set current session to match the key session
      mock_serai.set_session(network.into(), Session(0)).await;
      txn.commit();
    }

    // Verify keys exist before running
    {
      let txn = task_test.db.txn();
      assert!(
        crate::_public_db::NetworksSetKeysTransaction::get(&txn, network).is_some(),
        "keys should exist before task runs"
      );
    }

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    // Keys should have been consumed from DB
    {
      let txn = task_test.db.txn();
      assert!(
        crate::_public_db::NetworksSetKeysTransaction::get(&txn, network).is_none(),
        "keys should have been consumed from DB after publishing"
      );
    }
  }

  #[tokio::test]
  async fn drains_retired_keys() {
    // Keys are for a session that has been retired (current_session > key_session) = Ok(false)
    let (mock_serai, mut task_test) = SetKeysTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let network = ExternalNetworkId::Bitcoin;
    let set = ExternalValidatorSet { network, session: Session(0) };

    {
      let mut txn = task_test.db.txn();
      NetworksSetKeysTransaction::set(
        &mut txn,
        set,
        random_key_pair(&mut OsRng),
        random_signature_participants(&mut OsRng),
        Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
      );
      // Current session is 5, key session is 0 = retired
      mock_serai.set_session(network.into(), Session(5)).await;
      txn.commit();
    }

    // Verify keys exist before running
    {
      let txn = task_test.db.txn();
      assert!(
        crate::_public_db::NetworksSetKeysTransaction::get(&txn, network).is_some(),
        "keys should exist before task runs"
      );
    }

    let mut task = task_test.task();
    // Returns Ok(false): no progress made, but the retired keys are drained
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;

    // Keys should have been drained
    {
      let txn = task_test.db.txn();
      assert!(
        crate::_public_db::NetworksSetKeysTransaction::get(&txn, network).is_none(),
        "retired keys should have been drained"
      );
    }
  }

  #[tokio::test]
  async fn drains_when_keys_already_set_on_serai() {
    // Keys are for the current session, but already set on Serai = Ok(false)
    let (mock_serai, mut task_test) = SetKeysTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let network = ExternalNetworkId::Bitcoin;
    let set = ExternalValidatorSet { network, session: Session(0) };
    let key_pair = random_key_pair(&mut OsRng);

    {
      let mut txn = task_test.db.txn();
      NetworksSetKeysTransaction::set(
        &mut txn,
        set,
        key_pair.clone(),
        random_signature_participants(&mut OsRng),
        Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
      );
      // Set current session to match the key session
      mock_serai.set_session(network.into(), Session(0)).await;
      // Keys already set on Serai for this set
      mock_serai.set_key(set, key_pair.clone()).await;
      txn.commit();
    }

    // Verify keys exist before running
    {
      let txn = task_test.db.txn();
      assert!(
        crate::_public_db::NetworksSetKeysTransaction::get(&txn, network).is_some(),
        "keys should exist before task runs"
      );
    }

    let mut task = task_test.task();
    // Returns Ok(false): no progress made, but keys are drained since already set
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;

    // Keys should have been drained
    {
      let txn = task_test.db.txn();
      assert!(
        crate::_public_db::NetworksSetKeysTransaction::get(&txn, network).is_none(),
        "keys should have been drained since already set on Serai"
      );
    }
  }

  #[tokio::test]
  async fn errors_when_session_yet_to_start() {
    // Keys are for a session that Serai has not yet started (key_session > current_session) = error
    let (mock_serai, mut task_test) = SetKeysTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let network = ExternalNetworkId::Bitcoin;
    let set = ExternalValidatorSet { network, session: Session(5) };

    {
      let mut txn = task_test.db.txn();
      NetworksSetKeysTransaction::set(
        &mut txn,
        set,
        random_key_pair(&mut OsRng),
        random_signature_participants(&mut OsRng),
        Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
      );
      // Current session is 0, key session is 5 = Serai hasn't started this session yet
      mock_serai.set_session(network.into(), Session(0)).await;
      txn.commit();
    }

    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(
        &mut task,
        "have a keys for a session Serai has yet to start",
      )
      .await;
    }

    // Keys should NOT have been drained (task errored, txn not committed)
    {
      let txn = task_test.db.txn();
      assert!(
        crate::_public_db::NetworksSetKeysTransaction::get(&txn, network).is_some(),
        "keys should NOT have been drained when task errors"
      );
    }
  }

  #[tokio::test]
  async fn verifies_db_invariants_after_publish() {
    // Verify that DB invariants hold after a successful publish
    let (mock_serai, mut task_test) = SetKeysTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let network = ExternalNetworkId::Bitcoin;
    let set = ExternalValidatorSet { network, session: Session(0) };

    {
      let mut txn = task_test.db.txn();
      NetworksSetKeysTransaction::set(
        &mut txn,
        set,
        random_key_pair(&mut OsRng),
        random_signature_participants(&mut OsRng),
        Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
      );
      mock_serai.set_session(network.into(), Session(0)).await;
      txn.commit();
    }

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    // After publishing, keys should be drained (current_session >= key_session)
    let mut current_sessions = std::collections::HashMap::new();
    current_sessions.insert(network, Session(0));
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      &[(network, set.session)],
      &current_sessions,
    );
  }

  #[tokio::test]
  async fn verifies_db_invariants_after_retired_drain() {
    // Verify that DB invariants hold when keys are drained as retired
    let (mock_serai, mut task_test) = SetKeysTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let network = ExternalNetworkId::Bitcoin;
    let set = ExternalValidatorSet { network, session: Session(0) };

    {
      let mut txn = task_test.db.txn();
      NetworksSetKeysTransaction::set(
        &mut txn,
        set,
        random_key_pair(&mut OsRng),
        random_signature_participants(&mut OsRng),
        Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
      );
      mock_serai.set_session(network.into(), Session(5)).await;
      txn.commit();
    }

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;

    // Keys should be drained (current_session > key_session)
    let mut current_sessions = std::collections::HashMap::new();
    current_sessions.insert(network, Session(5));
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      &[(network, set.session)],
      &current_sessions,
    );
  }

  #[tokio::test]
  async fn verifies_db_invariants_after_already_set_drain() {
    // Verify that DB invariants hold when keys are drained because already set on Serai
    let (mock_serai, mut task_test) = SetKeysTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let network = ExternalNetworkId::Bitcoin;
    let set = ExternalValidatorSet { network, session: Session(0) };
    let key_pair = random_key_pair(&mut OsRng);

    {
      let mut txn = task_test.db.txn();
      NetworksSetKeysTransaction::set(
        &mut txn,
        set,
        key_pair.clone(),
        random_signature_participants(&mut OsRng),
        Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
      );
      mock_serai.set_session(network.into(), Session(0)).await;
      mock_serai.set_key(set, key_pair).await;
      txn.commit();
    }

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;

    // Keys should be drained (current_session >= key_session)
    let mut current_sessions = std::collections::HashMap::new();
    current_sessions.insert(network, Session(0));
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      &[(network, set.session)],
      &current_sessions,
    );
  }

  #[tokio::test]
  async fn processes_multiple_networks() {
    // Keys for multiple networks are processed in a single iteration
    let (mock_serai, mut task_test) = SetKeysTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let btc_network = ExternalNetworkId::Bitcoin;
    let eth_network = ExternalNetworkId::Ethereum;
    let btc_set = ExternalValidatorSet { network: btc_network, session: Session(0) };
    let eth_set = ExternalValidatorSet { network: eth_network, session: Session(0) };

    {
      let mut txn = task_test.db.txn();
      NetworksSetKeysTransaction::set(
        &mut txn,
        btc_set,
        random_key_pair(&mut OsRng),
        random_signature_participants(&mut OsRng),
        Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
      );
      NetworksSetKeysTransaction::set(
        &mut txn,
        eth_set,
        random_key_pair(&mut OsRng),
        random_signature_participants(&mut OsRng),
        Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
      );
      // Set current sessions to match the key sessions for both networks
      mock_serai.set_session(btc_network.into(), Session(0)).await;
      mock_serai.set_session(eth_network.into(), Session(0)).await;
      txn.commit();
    }

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    // Both networks' keys should have been consumed
    {
      let txn = task_test.db.txn();
      assert!(
        crate::_public_db::NetworksSetKeysTransaction::get(&txn, btc_network).is_none(),
        "Bitcoin keys should have been consumed"
      );
      assert!(
        crate::_public_db::NetworksSetKeysTransaction::get(&txn, eth_network).is_none(),
        "Ethereum keys should have been consumed"
      );
    }
  }
}

#[tokio::test]
async fn handles_older_recent_pair_of_keys() {
  let (mock_serai, mut task_test) = SetKeysTestStruct::setup_mock_test().await;
  let (block_hashes, ..) = mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

  mock_serai.remove_block(block_hashes.last().unwrap().0).await;

  let set0 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) };
  {
    let mut txn = task_test.db.txn();
    NetworksSetKeysTransaction::set(
      &mut txn,
      set0,
      random_key_pair(&mut OsRng),
      random_signature_participants(&mut OsRng),
      Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
    );
    txn.commit();
  }

  let set1 = ExternalValidatorSet { network: set0.network, session: Session(set0.session.0 + 1) };
  {
    let mut txn = task_test.db.txn();
    NetworksSetKeysTransaction::set(
      &mut txn,
      set1,
      random_key_pair(&mut OsRng),
      random_signature_participants(&mut OsRng),
      Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
    );
    txn.commit();
  }

  let txn = task_test.db.txn();
  assert_eq!(
    crate::_public_db::NetworksSetKeysTransaction::get(&txn, set1.network).unwrap().0,
    Session(1),
    "keys should exist before task runs"
  );
}

#[tokio::test]
async fn handles_more_recent_pair_of_keys() {
  let (mock_serai, mut task_test) = SetKeysTestStruct::setup_mock_test().await;
  let (block_hashes, ..) = mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

  mock_serai.remove_block(block_hashes.last().unwrap().0).await;

  let set1 = ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(1) };
  {
    let mut txn = task_test.db.txn();
    NetworksSetKeysTransaction::set(
      &mut txn,
      set1,
      random_key_pair(&mut OsRng),
      random_signature_participants(&mut OsRng),
      Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
    );
    txn.commit();
  }

  let set0 = ExternalValidatorSet { network: set1.network, session: Session(set1.session.0 - 1) };
  {
    let mut txn = task_test.db.txn();
    NetworksSetKeysTransaction::set(
      &mut txn,
      set0,
      random_key_pair(&mut OsRng),
      random_signature_participants(&mut OsRng),
      Signature::Ristretto(random_ristretto_signature(&mut OsRng)),
    );
    txn.commit();
  }

  let txn = task_test.db.txn();
  assert_eq!(
    crate::_public_db::NetworksSetKeysTransaction::get(&txn, set0.network).unwrap().0,
    Session(1),
    "keys should exist before task runs"
  );
}
