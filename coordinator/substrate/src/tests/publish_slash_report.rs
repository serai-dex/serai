use std::collections::HashMap;
use rand::RngCore;
use rand_core::OsRng;
use serai_primitives::{
  network_id::ExternalNetworkId,
  test_helpers::{random_external_network_id, random_external_validator_set, random_slash_report},
  validator_sets::{ExternalValidatorSet, Session},
};
use serai_db::MemDbTxn;

use serai_client_serai::{
  Serai,
  abi::primitives::crypto::{Signature, RistrettoSignature},
};
use serai_mock_rpc::MockSeraiRpc;
use serai_mock_rpc::block_events_fuzzer::BlockEventsFuzzer;
use serai_task::test_helpers::IntoMockSerai;

use crate::{PublishSlashReportTask, NetworksSlashReports};
use super::*;

pub(crate) struct PublishSlashReportTestStruct {
  pub(crate) serai: Arc<Serai>,
  pub(crate) db: MemDb,
}

serai_task::impl_serai_task_test_struct!(PublishSlashReportTestStruct);

impl IntoTask for PublishSlashReportTestStruct {
  type Task = PublishSlashReportTask<MemDb>;

  fn task(&self) -> Self::Task {
    PublishSlashReportTask::new(self.db.clone(), self.serai.clone())
  }
}

impl IntoMockSerai for PublishSlashReportTestStruct {}

/// Verify DB invariants for slash reports after the task runs.
fn verify_db_invariants_for_network_and_events(
  db: &mut MemDb,
  networks_with_sessions: &[(ExternalNetworkId, Session)],
  current_sessions: &HashMap<ExternalNetworkId, Session>,
) {
  let txn = db.txn();

  for (network, slash_session) in networks_with_sessions {
    let current = current_sessions.get(network);
    let should_be_drained = current.is_some_and(|cs| cs.0 >= slash_session.0 + 2);
    let exists = crate::_public_db::NetworksSlashReportsTransaction::get(&txn, *network);

    if should_be_drained {
      assert!(
        exists.is_none(),
        "network {network:?} slash {slash_session:?} current {current:?} \
         should have been drained, but slash report still exists"
      );
    } else {
      assert!(
        exists.is_some(),
        "network {network:?} slash {slash_session:?} current {current:?} \
         should NOT have been drained, but slash report is missing"
      );
    }
  }
}

fn random_ristretto_signature(rng: &mut impl RngCore) -> RistrettoSignature {
  let mut bytes = [0u8; 64];
  rng.fill_bytes(&mut bytes);
  RistrettoSignature(bytes)
}

async fn seed_slash_reports(txn: &mut MemDbTxn<'_>, mock_serai: &mut MockSeraiRpc) {
  let set = random_external_validator_set(&mut OsRng);
  let slash_report = random_slash_report(&mut OsRng);
  let signature = Signature::Ristretto(random_ristretto_signature(&mut OsRng));

  mock_serai.set_session(set.network.into(), Session(set.session.0 + 2)).await;

  NetworksSlashReports::set(txn, set, slash_report, signature);
}

mod errors {
  use super::*;

  #[tokio::test]
  async fn handles_serai_state_rpc_error() {
    let (mut mock_serai, mut task_test) = PublishSlashReportTestStruct::setup_mock_test().await;
    let (block_hashes, ..) = mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    mock_serai.remove_block(block_hashes.last().unwrap().0).await;

    {
      let mut txn = task_test.db.txn();
      seed_slash_reports(&mut txn, &mut mock_serai).await;
      txn.commit();
    }

    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching serai state").await;
    }
  }

  #[tokio::test]
  async fn handles_serai_current_session_rpc_error() {
    let (mut mock_serai, mut task_test) = PublishSlashReportTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    mock_serai.set_error("validator-sets/current_session", "timeout").await;

    {
      let mut txn = task_test.db.txn();
      seed_slash_reports(&mut txn, &mut mock_serai).await;
      txn.commit();
    }

    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching current session").await;
    }
  }

  #[tokio::test]
  async fn handles_serai_pending_slash_report_rpc_error() {
    let (mut mock_serai, mut task_test) = PublishSlashReportTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    mock_serai.set_error("validator-sets/pending_slash_report", "timeout").await;

    {
      let mut txn = task_test.db.txn();
      seed_slash_reports(&mut txn, &mut mock_serai).await;
      txn.commit();
    }

    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(&mut task, "RPC error fetching pending slash report")
        .await;
    }
  }

  #[tokio::test]
  async fn handles_serai_publish_transaction_rpc_error() {
    let (mut mock_serai, mut task_test) = PublishSlashReportTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    mock_serai.set_error("blockchain/publish_transaction", "timeout").await;

    {
      let mut txn = task_test.db.txn();
      seed_slash_reports(&mut txn, &mut mock_serai).await;
      txn.commit();
    }

    let mut task = task_test.task();
    {
      TaskTest::task_runs_and_fails_with(&mut task, "couldn't publish slash report transaction")
        .await;
    }
  }
}

mod progresses {
  use super::*;

  #[tokio::test]
  async fn handles_empty_slash_reports() {
    let (_, task_test) = PublishSlashReportTestStruct::setup_mock_test().await;
    let mut task = task_test.task();
    {
      TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
    }
  }

  #[tokio::test]
  async fn processes_pending_slash_reports() {
    let (mock_serai, mut task_test) = PublishSlashReportTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let set0 =
      ExternalValidatorSet { network: random_external_network_id(&mut OsRng), session: Session(0) };

    // Attempt to slash report the current session fails with yet to retire
    {
      {
        let slash_report = random_slash_report(&mut OsRng);
        let signature = Signature::Ristretto(random_ristretto_signature(&mut OsRng));

        mock_serai.set_session(set0.network.into(), set0.session).await;

        let mut txn = task_test.db.txn();
        NetworksSlashReports::set(&mut txn, set0, slash_report, signature);
        txn.commit();
      }

      let mut task = task_test.task();
      {
        TaskTest::task_runs_and_fails_with(
          &mut task,
          "have a slash report for a session Serai has yet to retire",
        )
        .await;
      }

      // current_session (0) < slash_session (0) + 2 => should NOT be drained
      let mut current_sessions = HashMap::new();
      current_sessions.insert(set0.network, Session(0));
      verify_db_invariants_for_network_and_events(
        &mut task_test.db,
        &[(set0.network, set0.session)],
        &current_sessions,
      );
    }

    // Attempt to slash report the session #n+1 fails with yet to retire
    {
      {
        // re-use set0's network but just increase the session
        let set1 = ExternalValidatorSet { network: set0.network, session: Session(1) };
        let slash_report = random_slash_report(&mut OsRng);
        let signature = Signature::Ristretto(random_ristretto_signature(&mut OsRng));

        mock_serai.set_session(set1.network.into(), set1.session).await;

        let mut txn = task_test.db.txn();
        NetworksSlashReports::set(&mut txn, set0, slash_report, signature);
        txn.commit();
      }

      let mut task = task_test.task();
      {
        TaskTest::task_runs_and_fails_with(
          &mut task,
          "have a slash report for a session Serai has yet to retire",
        )
        .await;
      }

      // current_session (1) < slash_session (0) + 2 => should NOT be drained
      let mut current_sessions = HashMap::new();
      current_sessions.insert(set0.network, Session(1));
      verify_db_invariants_for_network_and_events(
        &mut task_test.db,
        &[(set0.network, set0.session)],
        &current_sessions,
      );
    }

    // Attempt to slash report the session #n+2 progresses
    {
      {
        // re-use set0's network but just increase the session
        let set2 = ExternalValidatorSet { network: set0.network, session: Session(2) };
        let slash_report = random_slash_report(&mut OsRng);
        let signature = Signature::Ristretto(random_ristretto_signature(&mut OsRng));

        mock_serai.set_session(set2.network.into(), set2.session).await;

        let mut txn = task_test.db.txn();
        NetworksSlashReports::set(&mut txn, set0, slash_report, signature);
        txn.commit();
      }

      let mut task = task_test.task();
      {
        TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
      }

      // current_session (2) >= slash_session (0) + 2 => should be drained
      let mut current_sessions = HashMap::new();
      current_sessions.insert(set0.network, Session(2));
      verify_db_invariants_for_network_and_events(
        &mut task_test.db,
        &[(set0.network, set0.session)],
        &current_sessions,
      );
    }
  }

  #[tokio::test]
  async fn drains_retired_slash_report() {
    let (mock_serai, mut task_test) = PublishSlashReportTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    // Slash report is for session 0, but current session is 5 (> 0+2=2), so it's retired
    let set =
      ExternalValidatorSet { network: random_external_network_id(&mut OsRng), session: Session(0) };
    let slash_report = random_slash_report(&mut OsRng);
    let signature = Signature::Ristretto(random_ristretto_signature(&mut OsRng));

    {
      // Current session is 5, slash report is for session 0,
      // active_session_after_slash_report = Session(0+2) = Session(2)
      // 5 > 2 => session_after_slash_report_retired = true
      mock_serai.set_session(set.network.into(), Session(5)).await;
    }

    {
      let mut txn = task_test.db.txn();
      NetworksSlashReports::set(&mut txn, set, slash_report, signature);
      txn.commit();
    }

    // Verify the slash report exists before running the task
    {
      let txn = task_test.db.txn();
      assert!(
        crate::_public_db::NetworksSlashReportsTransaction::get(&txn, set.network).is_some(),
        "slash report should exist before task runs"
      );
    }

    let mut task = task_test.task();
    // Returns Ok(false): no progress made, but the retired slash report is drained
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;

    // current_session (5) >= slash_session (0) + 2 => should be drained
    let mut current_sessions = HashMap::new();
    current_sessions.insert(set.network, Session(5));
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      &[(set.network, set.session)],
      &current_sessions,
    );
  }

  #[tokio::test]
  async fn drains_when_pending_slash_report_is_false() {
    let (mock_serai, mut task_test) = PublishSlashReportTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    // Slash report is for session 0, current session is 2 (== 0+2), so it's not retired
    let set =
      ExternalValidatorSet { network: random_external_network_id(&mut OsRng), session: Session(0) };
    let slash_report = random_slash_report(&mut OsRng);
    let signature = Signature::Ristretto(random_ristretto_signature(&mut OsRng));

    {
      // Current session is 2, slash report is for session 0,
      // active_session_after_slash_report = Session(0+2) = Session(2)
      // 2 == 2 => not retired, passes the session check
      mock_serai.set_session(set.network.into(), Session(2)).await;
      // pending_slash_report returns false for this network
      mock_serai.set_pending_slash_report(set.network, false).await;
    }

    {
      let mut txn = task_test.db.txn();
      NetworksSlashReports::set(&mut txn, set, slash_report, signature);
      txn.commit();
    }

    // Verify the slash report exists before running the task
    {
      let txn = task_test.db.txn();
      assert!(
        crate::_public_db::NetworksSlashReportsTransaction::get(&txn, set.network).is_some(),
        "slash report should exist before task runs"
      );
    }

    let mut task = task_test.task();
    // Returns Ok(false) - no progress made, but the non-pending slash report is drained
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;

    // current_session (2) >= slash_session (0) + 2 => should be drained
    let mut current_sessions = HashMap::new();
    current_sessions.insert(set.network, Session(2));
    verify_db_invariants_for_network_and_events(
      &mut task_test.db,
      &[(set.network, set.session)],
      &current_sessions,
    );
  }
}

#[tokio::test]
async fn handles_older_recent_pair_of_keys() {
  let (mock_serai, mut task_test) = PublishSlashReportTestStruct::setup_mock_test().await;
  mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

  let network = random_external_network_id(&mut OsRng);

  let set0 = ExternalValidatorSet { network, session: Session(0) };
  {
    let slash_report = random_slash_report(&mut OsRng);
    let signature = Signature::Ristretto(random_ristretto_signature(&mut OsRng));

    mock_serai.set_session(set0.network.into(), set0.session).await;

    let mut txn = task_test.db.txn();
    NetworksSlashReports::set(&mut txn, set0, slash_report, signature);
    txn.commit();
  }

  let set1 = ExternalValidatorSet { network, session: Session(1) };
  {
    let slash_report = random_slash_report(&mut OsRng);
    let signature = Signature::Ristretto(random_ristretto_signature(&mut OsRng));

    mock_serai.set_session(set1.network.into(), set1.session).await;

    let mut txn = task_test.db.txn();
    NetworksSlashReports::set(&mut txn, set1, slash_report, signature);
    txn.commit();
  }

  let txn = task_test.db.txn();
  assert_eq!(
    crate::_public_db::NetworksSlashReportsTransaction::get(&txn, network).unwrap().0,
    Session(1)
  );
}
