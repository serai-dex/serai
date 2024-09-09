use serai_db::{DbTxn, Db};

use primitives::task::ContinuallyRan;

use crate::{
  db::{
    RegisteredKeys, CosignerToCoordinatorMessages, BatchSignerToCoordinatorMessages,
    SlashReportSignerToCoordinatorMessages, TransactionSignerToCoordinatorMessages,
  },
  Coordinator,
};

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

    // TODO: For max(last acknowledged batch, last published batch) onwards, publish every batch

    Ok(iterated)
  }
}
