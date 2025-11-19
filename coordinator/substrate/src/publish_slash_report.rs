use core::future::Future;
use std::sync::Arc;

use serai_db::{DbTxn, Db};

use serai_client_serai::{
  abi::primitives::{network_id::ExternalNetworkId, validator_sets::Session},
  Serai,
};

use serai_task::ContinuallyRan;

use crate::SlashReports;

/// Publish slash reports from `SlashReports` onto Serai.
pub struct PublishSlashReportTask<D: Db> {
  db: D,
  serai: Arc<Serai>,
}

impl<D: Db> PublishSlashReportTask<D> {
  /// Create a task to publish slash reports onto Serai.
  pub fn new(db: D, serai: Arc<Serai>) -> Self {
    Self { db, serai }
  }
}

impl<D: Db> PublishSlashReportTask<D> {
  // Returns if a slash report was successfully published
  async fn publish(&mut self, network: ExternalNetworkId) -> Result<bool, String> {
    let mut txn = self.db.txn();
    let Some((session, slash_report)) = SlashReports::take(&mut txn, network) else {
      // No slash report to publish
      return Ok(false);
    };

    // This uses the latest finalized block, not the latest cosigned block, which should be
    // fine as in the worst case, the only impact is no longer attempting TX publication
    let serai = self.serai.state().await.map_err(|e| format!("{e:?}"))?;
    let session_after_slash_report = Session(session.0 + 1);
    let current_session =
      serai.current_session(network.into()).await.map_err(|e| format!("{e:?}"))?;
    let current_session = current_session.map(|session| session.0);
    // Only attempt to publish the slash report for session #n while session #n+1 is still
    // active
    let session_after_slash_report_retired = current_session > Some(session_after_slash_report.0);
    if session_after_slash_report_retired {
      // Commit the txn to drain this slash report from the database and not try it again later
      txn.commit();
      return Ok(false);
    }

    if Some(session_after_slash_report.0) != current_session {
      // We already checked the current session wasn't greater, and they're not equal
      assert!(current_session < Some(session_after_slash_report.0));
      // This would mean the Serai node is resyncing and is behind where it prior was
      Err("have a slash report for a session Serai has yet to retire".to_string())?;
    }

    // If this session which should publish a slash report already has, move on
    if !serai.pending_slash_report(network).await.map_err(|e| format!("{e:?}"))? {
      txn.commit();
      return Ok(false);
    };

    // Since this slash report is still pending, publish it
    match self.serai.publish_transaction(&slash_report).await {
      Ok(()) => {
        txn.commit();
        Ok(true)
      }
      // This could be specific to this TX (such as an already in mempool error) and it may be
      // worthwhile to continue iteration with the other pending slash reports. We assume this
      // error ephemeral and that the latency incurred for this ephemeral error to resolve is
      // miniscule compared to the window available to publish the slash report. That makes
      // this a non-issue.
      Err(e) => Err(format!("couldn't publish slash report transaction: {e:?}")),
    }
  }
}

impl<D: Db> ContinuallyRan for PublishSlashReportTask<D> {
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut made_progress = false;
      let mut error = None;
      for network in ExternalNetworkId::all() {
        let network_res = self.publish(network).await;
        // We made progress if any network successfully published their slash report
        made_progress |= network_res == Ok(true);
        // We want to yield the first error *after* attempting for every network
        error = error.or(network_res.err());
      }
      // Yield the error
      if let Some(error) = error {
        Err(error)?
      }
      Ok(made_progress)
    }
  }
}
