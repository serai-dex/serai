use rand::RngCore as _;
use rand_core::OsRng;
use serai_primitives::{
  network_id::ExternalNetworkId,
  test_helpers::random_block_hash,
  crypto::{Signature, RistrettoSignature},
  instructions::{Batch, SignedBatch},
};

use serai_mock_rpc::block_events_fuzzer::BlockEventsFuzzer;
use serai_client_serai::Serai;
use serai_task::test_helpers::IntoMockSerai;

use crate::{NetworksProcessorSignedBatches, PublishBatchTask, canonical::last_indexed_batch_id};
use crate::publish_batch::{LastPublishedBatch, PendingBatchesToPublish};
use super::*;

pub(crate) struct PublishBatchTestStruct {
  pub(crate) serai: Arc<Serai>,
  pub(crate) db: MemDb,
}

serai_task::impl_serai_task_test_struct!(PublishBatchTestStruct);

impl IntoTask for PublishBatchTestStruct {
  type Task = PublishBatchTask<MemDb>;

  fn task(&self) -> Self::Task {
    PublishBatchTask::new(self.db.clone(), self.serai.clone(), ExternalNetworkId::Bitcoin)
  }
}

impl IntoMockSerai for PublishBatchTestStruct {}

/// Create a random `SignedBatch` for the given network and batch ID.
fn random_signed_batch(network: ExternalNetworkId, id: u32) -> SignedBatch {
  let block_hash = random_block_hash(&mut OsRng);
  let batch = Batch::new(network, id, block_hash);
  let mut sig_bytes = [0u8; 64];
  OsRng.fill_bytes(&mut sig_bytes);
  SignedBatch { batch, signature: Signature::Ristretto(RistrettoSignature(sig_bytes)) }
}

/// Verify DB invariants for batch publishing after the task runs.
fn verify_db_invariants(
  db: &mut MemDb,
  network: ExternalNetworkId,
  batch_id: u32,
  should_be_in_batches_to_publish: bool,
) {
  let txn = db.txn();
  let last_indexed = last_indexed_batch_id(&txn, network);
  let in_batches_to_publish = PendingBatchesToPublish::get(&txn, network, batch_id).is_some();

  if should_be_in_batches_to_publish {
    assert!(
      in_batches_to_publish,
      "batch {batch_id} for network {network:?} should be in BatchesToPublish \
       (last_indexed={last_indexed:?}), but it is not"
    );
  } else {
    assert!(
      !in_batches_to_publish,
      "batch {batch_id} for network {network:?} should NOT be in BatchesToPublish \
       (last_indexed={last_indexed:?}), but it is"
    );
  }
}

mod errors {
  use super::*;

  #[tokio::test]
  async fn handles_serai_publish_transaction_rpc_error() {
    let (mock_serai, mut task_test) = PublishBatchTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    mock_serai.set_error("blockchain/publish_transaction", "timeout").await;

    // Seed a batch into SignedBatches
    let network = ExternalNetworkId::Bitcoin;
    let batch = random_signed_batch(network, 0);
    {
      let mut txn = task_test.db.txn();
      NetworksProcessorSignedBatches::send(&mut txn, &batch);
      txn.commit();
    }

    let mut task = task_test.task();
    TaskTest::task_runs_and_fails_with(&mut task, "timeout").await;
  }
}

mod progresses {
  use super::*;

  #[tokio::test]
  async fn handles_empty_signed_batches() {
    // No batches in SignedBatches, no batches to publish = Ok(false)
    let (_, task_test) = PublishBatchTestStruct::setup_mock_test().await;
    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
  }

  #[tokio::test]
  async fn publishes_batch_from_signed_batches() {
    // Batch is received from SignedBatches, saved to BatchesToPublish, and published = Ok(true)
    let (mock_serai, mut task_test) = PublishBatchTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let network = ExternalNetworkId::Bitcoin;
    let batch = random_signed_batch(network, 0);

    // Seed the batch into SignedBatches
    {
      let mut txn = task_test.db.txn();
      NetworksProcessorSignedBatches::send(&mut txn, &batch);
      txn.commit();
    }

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    // After publishing, the batch should have been consumed from SignedBatches
    // and still be in BatchesToPublish (cleanup only happens during sync when
    // last_indexed_batch_id advances past this batch)
    {
      let mut txn = task_test.db.txn();
      assert!(
        NetworksProcessorSignedBatches::try_recv(&mut txn, network).is_none(),
        "batch should have been consumed from SignedBatches"
      );
      assert!(
        PendingBatchesToPublish::get(&txn, network, 0).is_some(),
        "published batch should still be in BatchesToPublish (cleanup happens on sync)"
      );
    }
  }

  #[tokio::test]
  async fn skips_already_published_batch() {
    // Batch is in SignedBatches but LastPublishedBatch >= batch.id(),
    // so it is NOT saved to BatchesToPublish = Ok(false)
    let (mock_serai, mut task_test) = PublishBatchTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let network = ExternalNetworkId::Bitcoin;
    let batch = random_signed_batch(network, 0);

    // Set LastPublishedBatch to 1, which is >= batch.id() (0)
    {
      let mut txn = task_test.db.txn();
      LastPublishedBatch::set(&mut txn, network, &1);
      txn.commit();
    }

    // Seed the batch into SignedBatches
    {
      let mut txn = task_test.db.txn();
      NetworksProcessorSignedBatches::send(&mut txn, &batch);
      txn.commit();
    }

    let mut task = task_test.task();
    // No progress: batch was already published, so not saved to BatchesToPublish
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;

    // Verify the batch was consumed from SignedBatches but NOT added to BatchesToPublish
    {
      let mut txn = task_test.db.txn();
      assert!(
        NetworksProcessorSignedBatches::try_recv(&mut txn, network).is_none(),
        "batch should have been consumed from SignedBatches"
      );
      assert!(
        PendingBatchesToPublish::get(&txn, network, 0).is_none(),
        "already-published batch should NOT be in BatchesToPublish"
      );
    }
  }

  #[tokio::test]
  async fn cleans_up_already_indexed_batch() {
    // Batch is saved to BatchesToPublish, but last_indexed_batch_id already covers it,
    // so it gets cleaned up during sync = Ok(false)
    let (mock_serai, mut task_test) = PublishBatchTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let network = ExternalNetworkId::Bitcoin;
    let batch = random_signed_batch(network, 0);

    // Set LastIndexedBatchId to 1 (batch 0 is already indexed)
    {
      let mut txn = task_test.db.txn();
      crate::canonical::NetworksCanonicalLastIndexedBatchId::set(&mut txn, network, &1u32);
      txn.commit();
    }

    // Seed the batch into SignedBatches
    {
      let mut txn = task_test.db.txn();
      NetworksProcessorSignedBatches::send(&mut txn, &batch);
      txn.commit();
    }

    let mut task = task_test.task();
    // Batch is saved to BatchesToPublish, but sync cleans it up since it's already indexed
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;

    // Verify the batch was cleaned up from BatchesToPublish
    {
      let txn = task_test.db.txn();
      assert!(
        PendingBatchesToPublish::get(&txn, network, 0).is_none(),
        "already-indexed batch should have been cleaned up from BatchesToPublish"
      );
      // LastPublishedBatch should have been synced to 1
      assert_eq!(LastPublishedBatch::get(&txn, network), Some(1));
    }
  }

  #[tokio::test]
  async fn publishes_multiple_batches_sequentially() {
    // Multiple batches in SignedBatches are saved to BatchesToPublish,
    // then published one at a time across iterations.
    // Note: batches are NOT cleaned up after publishing locally - they remain
    // in BatchesToPublish until the canonical task advances last_indexed_batch_id.
    // This means the same batch may be re-published on subsequent iterations.
    let (mock_serai, mut task_test) = PublishBatchTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let network = ExternalNetworkId::Bitcoin;
    let batch0 = random_signed_batch(network, 0);
    let batch1 = random_signed_batch(network, 1);

    // Seed both batches into SignedBatches
    {
      let mut txn = task_test.db.txn();
      NetworksProcessorSignedBatches::send(&mut txn, &batch0);
      NetworksProcessorSignedBatches::send(&mut txn, &batch1);
      txn.commit();
    }

    // First iteration: publishes batch 0
    {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }

    // Verify both batches are in BatchesToPublish
    {
      let txn = task_test.db.txn();
      assert!(
        PendingBatchesToPublish::get(&txn, network, 0).is_some(),
        "batch 0 should be in BatchesToPublish"
      );
      assert!(
        PendingBatchesToPublish::get(&txn, network, 1).is_some(),
        "batch 1 should be in BatchesToPublish"
      );
    }

    // Second iteration: publishes batch 1
    {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }

    // Third iteration: batch 0 is still in BatchesToPublish (no sync happened),
    // so it gets re-published = Ok(true)
    {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }

    // Fourth iteration: batch 0 is still in BatchesToPublish = Ok(true)
    // (batches are only cleaned up when last_indexed_batch_id advances)
    {
      let mut task = task_test.task();
      TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;
    }
  }

  #[tokio::test]
  async fn verifies_db_invariants_after_publish() {
    // Verify that DB invariants hold after a successful publish
    let (mock_serai, mut task_test) = PublishBatchTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let network = ExternalNetworkId::Bitcoin;
    let batch = random_signed_batch(network, 0);

    // Seed the batch into SignedBatches
    {
      let mut txn = task_test.db.txn();
      NetworksProcessorSignedBatches::send(&mut txn, &batch);
      txn.commit();
    }

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    // After publishing, batch 0 should be in BatchesToPublish
    // (cleanup only happens during sync when last_indexed_batch_id advances)
    verify_db_invariants(&mut task_test.db, network, 0, true);
  }

  #[tokio::test]
  async fn verifies_db_invariants_after_skip() {
    // Verify that DB invariants hold when a batch is skipped (already published)
    let (mock_serai, mut task_test) = PublishBatchTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let network = ExternalNetworkId::Bitcoin;
    let batch = random_signed_batch(network, 3);

    // Set LastPublishedBatch to 5, which is >= batch.id() (3)
    {
      let mut txn = task_test.db.txn();
      LastPublishedBatch::set(&mut txn, network, &5);
      txn.commit();
    }

    // Seed the batch into SignedBatches
    {
      let mut txn = task_test.db.txn();
      NetworksProcessorSignedBatches::send(&mut txn, &batch);
      txn.commit();
    }

    let mut task = task_test.task();
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;

    // Batch 3 should NOT be in BatchesToPublish (it was already published)
    verify_db_invariants(&mut task_test.db, network, 3, false);
  }

  #[tokio::test]
  async fn sync_advances_next_to_publish() {
    // When last_indexed_batch_id is ahead of LastPublishedBatch,
    // sync cleans up intermediate batches and advances next_to_publish
    let (mock_serai, mut task_test) = PublishBatchTestStruct::setup_mock_test().await;
    mock_serai.fuzz_blocks(&mut BlockEventsFuzzer::new(OsRng), 1).await;

    let network = ExternalNetworkId::Bitcoin;

    // Set LastIndexedBatchId to 5 (batches 0-5 already indexed on Serai)
    {
      let mut txn = task_test.db.txn();
      crate::canonical::NetworksCanonicalLastIndexedBatchId::set(&mut txn, network, &5u32);
      txn.commit();
    }

    // Seed batches 3, 4, 6 into SignedBatches
    let batch3 = random_signed_batch(network, 3);
    let batch4 = random_signed_batch(network, 4);
    let batch6 = random_signed_batch(network, 6);
    {
      let mut txn = task_test.db.txn();
      NetworksProcessorSignedBatches::send(&mut txn, &batch3);
      NetworksProcessorSignedBatches::send(&mut txn, &batch4);
      NetworksProcessorSignedBatches::send(&mut txn, &batch6);
      txn.commit();
    }

    let mut task = task_test.task();
    // Batches 3, 4 are cleaned up (already indexed), batch 6 is published = Ok(true)
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    // Verify batches 3, 4 were cleaned up, batch 6 is still in BatchesToPublish
    {
      let txn = task_test.db.txn();
      assert!(
        PendingBatchesToPublish::get(&txn, network, 3).is_none(),
        "batch 3 should have been cleaned up (already indexed)"
      );
      assert!(
        PendingBatchesToPublish::get(&txn, network, 4).is_none(),
        "batch 4 should have been cleaned up (already indexed)"
      );
      assert!(
        PendingBatchesToPublish::get(&txn, network, 6).is_some(),
        "batch 6 should still be in BatchesToPublish"
      );
      // LastPublishedBatch should have been synced to 5
      assert_eq!(LastPublishedBatch::get(&txn, network), Some(5));
    }
  }
}
