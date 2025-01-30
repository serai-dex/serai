use core::{marker::PhantomData, future::Future};

use serai_db::{DbTxn, Db};

use serai_validator_sets_primitives::Session;

use primitives::task::{DoesNotError, ContinuallyRan};
use crate::{
  db::{BatchData, BatchToReportDb, BatchesToSign},
  substrate, ScannerFeed,
};

mod db;
use db::BatchDb;

// This task begins reporting Batches for signing once the pre-requisities are met.
#[allow(non_snake_case)]
pub(crate) struct ReportTask<D: Db, S: ScannerFeed> {
  db: D,
  _S: PhantomData<S>,
}

impl<D: Db, S: ScannerFeed> ReportTask<D, S> {
  pub(crate) fn new(db: D) -> Self {
    Self { db, _S: PhantomData }
  }
}

impl<D: Db, S: ScannerFeed> ContinuallyRan for ReportTask<D, S> {
  type Error = DoesNotError;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut made_progress = false;
      loop {
        let mut txn = self.db.txn();
        let Some(BatchData {
          session_to_sign_batch,
          external_key_for_session_to_sign_batch,
          batch,
        }) = BatchToReportDb::<S>::try_recv_batch(&mut txn)
        else {
          break;
        };

        /*
          If this is the handover Batch, the first Batch signed by a session which retires the
          prior validator set, then this should only be signed after the prior validator set's
          actions are fully validated.

          The new session will only be responsible for signing this Batch if the prior key has
          retired, successfully completed all its on-external-network actions.

          We check here the prior session has successfully completed all its on-Serai-network
          actions by ensuring we've validated all Batches expected from it. Only then do we sign
          the Batch confirming the handover.

          We also wait for the Batch confirming the handover to be accepted on-chain, ensuring we
          don't verify the prior session's Batches, sign the handover Batch and the following
          Batch, have the prior session publish a malicious Batch where our handover Batch should
          be, before our following Batch becomes our handover Batch.
        */
        if session_to_sign_batch != Session(0) {
          // We may have Session(1)'s first Batch be Batch 0 if Session(0) never publishes a
          // Batch. This is fine as we'll hit the distinct Session check and then set the correct
          // values into this DB entry. All other sessions must complete the handover process,
          // which requires having published at least one Batch
          let (last_session, first_batch) =
            BatchDb::last_session_to_sign_batch_and_first_batch(&txn).unwrap_or((Session(0), 0));
          // Because this boolean was expanded, we lose short-circuiting. That's fine
          let handover_batch = last_session != session_to_sign_batch;
          let batch_after_handover_batch =
            (last_session == session_to_sign_batch) && ((first_batch + 1) == batch.id);
          if handover_batch || batch_after_handover_batch {
            let verified_prior_batch = substrate::last_acknowledged_batch::<S>(&txn)
              // Since `batch.id = 0` in the Session(0)-never-published-a-Batch case, we don't
              // check `last_acknowledged_batch >= (batch.id - 1)` but instead this
              .map(|last_acknowledged_batch| (last_acknowledged_batch + 1) >= batch.id)
              // We've never verified any Batches
              .unwrap_or(false);
            if !verified_prior_batch {
              // Drop the txn to restore the Batch to report to the DB
              drop(txn);
              break;
            }
          }

          // If this is the handover Batch, update the last session to sign a Batch
          if handover_batch {
            BatchDb::set_last_session_to_sign_batch_and_first_batch(
              &mut txn,
              session_to_sign_batch,
              batch.id,
            );
          }
        }

        BatchesToSign::send(&mut txn, &external_key_for_session_to_sign_batch.0, &batch);
        txn.commit();

        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
