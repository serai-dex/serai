//! Publish slash reports task, receives new signed slash reports from the processor and
//! attempts to publish to the Serai chain.
use core::future::Future;
use std::sync::Arc;

use serai_db::{DbTxn as _, Db};

use serai_client_serai::{
  abi::primitives::{
    network_id::ExternalNetworkId,
    validator_sets::{Session, ExternalValidatorSet},
  },
  Serai,
};

use serai_task::ContinuallyRan;

use crate::NetworksSlashReports;

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

  // Returns if a slash report was successfully published
  async fn publish(&mut self, network: ExternalNetworkId) -> Result<bool, String> {
    let mut txn = self.db.txn();
    let Some((session, this_networks_slash_report)) = NetworksSlashReports::take(&mut txn, network)
    else {
      // No slash report to publish
      return Ok(false);
    };

    // This uses the latest finalized block, not the latest cosigned block, which should be
    // fine as in the worst case, the only impact is no longer attempting TX publication
    let serai =
      self.serai.state().await.map_err(|e| format!("RPC error fetching serai state: {e:?}"))?;

    let current_networks_session = serai
      .current_session(network.into())
      .await
      .map_err(|e| format!("RPC error fetching current session: {e:?}"))?;
    let current_networks_session = current_networks_session.map(|session| session.0);

    // The timely session after this slash report represents the timeline as we only attempt
    // to publish the slash report for session #n while session #n+2 is still active
    let timely_session_after_this_slash_report = Session(session.0 + 2);

    let is_current_slash_report_session_historic =
      current_networks_session > Some(timely_session_after_this_slash_report.0);
    if is_current_slash_report_session_historic {
      // This slash report was not published in a timely manner, do not attempt publication
      // Commit the txn to drain this slash report from the database and not try it again later
      txn.commit();
      return Ok(false);
    }

    if Some(timely_session_after_this_slash_report.0) != current_networks_session {
      // We already checked the current session wasn't greater, and they're not equal
      assert!(current_networks_session < Some(timely_session_after_this_slash_report.0));
      // This would mean the Serai node is resyncing and is behind where it prior was
      Err("have a slash report for a session Serai has yet to retire".to_owned())?;
    }

    // If this session which should publish a slash report already has, move on
    if !serai
      .pending_slash_report(ExternalValidatorSet { network, session })
      .await
      .map_err(|e| format!("RPC error fetching pending slash report: {e:?}"))?
    {
      txn.commit();
      return Ok(false);
    }

    // Since this slash report is still pending, publish it
    match self.serai.publish_transaction(&this_networks_slash_report).await {
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
      for i_network in ExternalNetworkId::all() {
        let networks_response = self.publish(i_network).await;
        // We made progress if any network successfully published their slash report
        made_progress |= networks_response == Ok(true);
        // We want to yield the first error *after* attempting for every network
        error = error.or(networks_response.err());
      }
      // Yield the error
      if let Some(error) = error {
        Err(error)?;
      }
      Ok(made_progress)
    }
  }
}
