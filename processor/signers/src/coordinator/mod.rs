use serai_db::{DbTxn, Db};

use primitives::task::ContinuallyRan;

use crate::{
  db::{
    RegisteredKeys, CosignerToCoordinatorMessages, BatchSignerToCoordinatorMessages,
    SlashReportSignerToCoordinatorMessages, TransactionSignerToCoordinatorMessages,
  },
  Coordinator,
};

mod db;

// Fetches messages to send the coordinator and sends them.
pub(crate) struct CoordinatorTask<D: Db, C: Coordinator> {
  db: D,
  coordinator: C,
}

impl<D: Db, C: Coordinator> CoordinatorTask<D, C> {
  pub(crate) fn new(db: D, coordinator: C) -> Self {
    Self { db, coordinator }
  }
}

#[async_trait::async_trait]
impl<D: Db, C: Coordinator> ContinuallyRan for CoordinatorTask<D, C> {
  async fn run_iteration(&mut self) -> Result<bool, String> {
    let mut iterated = false;

    for session in RegisteredKeys::get(&self.db).unwrap_or(vec![]) {
      loop {
        let mut txn = self.db.txn();
        let Some(msg) = CosignerToCoordinatorMessages::try_recv(&mut txn, session) else {
          break;
        };
        iterated = true;

        self
          .coordinator
          .send(msg)
          .await
          .map_err(|e| format!("couldn't send sign message to the coordinator: {e:?}"))?;

        txn.commit();
      }

      loop {
        let mut txn = self.db.txn();
        let Some(msg) = BatchSignerToCoordinatorMessages::try_recv(&mut txn, session) else {
          break;
        };
        iterated = true;

        self
          .coordinator
          .send(msg)
          .await
          .map_err(|e| format!("couldn't send sign message to the coordinator: {e:?}"))?;

        txn.commit();
      }

      loop {
        let mut txn = self.db.txn();
        let Some(msg) = SlashReportSignerToCoordinatorMessages::try_recv(&mut txn, session) else {
          break;
        };
        iterated = true;

        self
          .coordinator
          .send(msg)
          .await
          .map_err(|e| format!("couldn't send sign message to the coordinator: {e:?}"))?;

        txn.commit();
      }

      loop {
        let mut txn = self.db.txn();
        let Some(msg) = TransactionSignerToCoordinatorMessages::try_recv(&mut txn, session) else {
          break;
        };
        iterated = true;

        self
          .coordinator
          .send(msg)
          .await
          .map_err(|e| format!("couldn't send sign message to the coordinator: {e:?}"))?;

        txn.commit();
      }
    }

    // Publish the Batches
    {
      let mut txn = self.db.txn();
      while let Some(batch) = scanner::Batches::try_recv(&mut txn) {
        iterated = true;
        self
          .coordinator
          .publish_batch(batch)
          .await
          .map_err(|e| format!("couldn't publish Batch: {e:?}"))?;
      }
      txn.commit();
    }

    // Publish the signed Batches
    {
      let mut txn = self.db.txn();
      // The last acknowledged Batch may exceed the last Batch we published if we didn't sign for
      // the prior Batch(es) (and accordingly didn't publish them)
      let last_batch =
        crate::batch::last_acknowledged_batch(&txn).max(db::LastPublishedBatch::get(&txn));
      let mut next_batch = last_batch.map_or(0, |id| id + 1);
      while let Some(batch) = crate::batch::signed_batch(&txn, next_batch) {
        iterated = true;
        db::LastPublishedBatch::set(&mut txn, &batch.batch.id);
        self
          .coordinator
          .publish_signed_batch(batch)
          .await
          .map_err(|e| format!("couldn't publish Batch: {e:?}"))?;
        next_batch += 1;
      }
      txn.commit();
    }

    Ok(iterated)
  }
}
