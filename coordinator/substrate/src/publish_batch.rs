//! Publish batch task, receives new batches from the processor and attempts to publish
//! to the Serai chain.
use core::future::Future;
use std::sync::Arc;

use serai_client_serai::{
  abi::primitives::{network_id::ExternalNetworkId, instructions::SignedBatch},
  RpcError, Serai,
};

use serai_db::{Get, DbTxn, Db, create_db};
use serai_task::ContinuallyRan;

create_db!(
  CoordinatorSubstratePublishBatch {
    LastPublishedBatch: (network: ExternalNetworkId) -> u32,
    PendingBatchesToPublish: (network: ExternalNetworkId, batch: u32) -> SignedBatch,
  }
);

/// Publish `SignedBatch`s from `SignedBatches` onto Serai.
pub struct PublishBatchTask<D: Db> {
  db: D,
  serai: Arc<Serai>,
  network: ExternalNetworkId,
}

impl<D: Db> PublishBatchTask<D> {
  /// Create a task to publish `SignedBatch`s onto Serai.
  pub fn new(db: D, serai: Arc<Serai>, network: ExternalNetworkId) -> Self {
    Self { db, serai, network }
  }
}

impl<D: Db> ContinuallyRan for PublishBatchTask<D> {
  type Error = RpcError;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      // Read from crate::NetworksProcessorSignedBatches, which is sequential, into our own mapping
      loop {
        let mut txn = self.db.txn();
        let Some(batch) = crate::NetworksProcessorSignedBatches::try_recv(&mut txn, self.network)
        else {
          break;
        };

        // If this is a Batch not yet published, save it into our unordered mapping
        if LastPublishedBatch::get(&txn, self.network) < Some(batch.batch.id()) {
          PendingBatchesToPublish::set(&mut txn, self.network, batch.batch.id(), &batch);
        }

        txn.commit();
      }

      // Synchronize our last published batch with the Serai network's
      let next_batch_to_publish = {
        let mut txn = self.db.txn();
        let last_indexed_batch = crate::canonical::last_indexed_batch_id(&txn, self.network);
        let mut our_last_published_batch = LastPublishedBatch::get(&txn, self.network);

        while our_last_published_batch < last_indexed_batch {
          let next_batch_that_needs_publish =
            our_last_published_batch.map(|batch| batch + 1).unwrap_or(0);

          // Clean up the pending Batch to publish since it's already been published
          PendingBatchesToPublish::take(&mut txn, self.network, next_batch_that_needs_publish);
          our_last_published_batch = Some(next_batch_that_needs_publish);
        }

        if let Some(last_published_batch) = our_last_published_batch {
          LastPublishedBatch::set(&mut txn, self.network, &last_published_batch);
        }
        txn.commit();

        // return next_batch_to_publish as the 1 increment of serai's latest batch indexed
        last_indexed_batch.map(|batch| batch + 1).unwrap_or(0)
      };

      let mut made_progress = false;

      if let Some(new_pending_batch) =
        PendingBatchesToPublish::get(&self.db, self.network, next_batch_to_publish)
      {
        self
          .serai
          .publish_transaction(&serai_client_serai::InInstructions::execute_batch(
            new_pending_batch,
          ))
          .await?;
        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}
