use core::future::Future;
use std::sync::Arc;

use serai_db::{DbTxn, Db};

use serai_client_serai::{
  abi::primitives::{network_id::ExternalNetworkId, validator_sets::ExternalValidatorSet},
  Serai,
};

use serai_task::ContinuallyRan;

use crate::Keys;

/// Set keys from `Keys` on Serai.
pub struct SetKeysTask<D: Db> {
  db: D,
  serai: Arc<Serai>,
}

impl<D: Db> SetKeysTask<D> {
  /// Create a task to publish slash reports onto Serai.
  pub fn new(db: D, serai: Arc<Serai>) -> Self {
    Self { db, serai }
  }
}

impl<D: Db> ContinuallyRan for SetKeysTask<D> {
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut made_progress = false;
      for network in ExternalNetworkId::all() {
        let mut txn = self.db.txn();
        let Some((session, keys)) = Keys::take(&mut txn, network) else {
          // No keys to set
          continue;
        };

        // This uses the latest finalized block, not the latest cosigned block, which should be
        // fine as in the worst case, the only impact is no longer attempting TX publication
        let serai =
          self.serai.as_of_latest_finalized_block().await.map_err(|e| format!("{e:?}"))?;
        let serai = serai.validator_sets();
        let current_session =
          serai.current_session(network.into()).await.map_err(|e| format!("{e:?}"))?;
        let current_session = current_session.map(|session| session.0);
        // Only attempt to set these keys if this isn't a retired session
        if Some(session.0) < current_session {
          // Commit the txn to take these keys from the database and not try it again later
          txn.commit();
          continue;
        }

        if Some(session.0) != current_session {
          // We already checked the current session wasn't greater, and they're not equal
          assert!(current_session < Some(session.0));
          // This would mean the Serai node is resyncing and is behind where it prior was
          Err("have a keys for a session Serai has yet to start".to_string())?;
        }

        // If this session already has had its keys set, move on
        if serai
          .keys(ExternalValidatorSet { network, session })
          .await
          .map_err(|e| format!("{e:?}"))?
          .is_some()
        {
          txn.commit();
          continue;
        };

        match self.serai.publish_transaction(&keys).await {
          Ok(()) => {
            txn.commit();
            made_progress = true;
          }
          // This could be specific to this TX (such as an already in mempool error) and it may be
          // worthwhile to continue iteration with the other pending slash reports. We assume this
          // error ephemeral and that the latency incurred for this ephemeral error to resolve is
          // miniscule compared to the window reasonable to set the keys. That makes this a
          // non-issue.
          Err(e) => Err(format!("couldn't publish set keys transaction: {e:?}"))?,
        }
      }
      Ok(made_progress)
    }
  }
}
