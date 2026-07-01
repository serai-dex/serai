use core::time::Duration;
use std::time::Instant;

use blake2::{Digest as _, Blake2s256};

use serai_primitives::test_helpers::random_bytes;
use serai_task::test_helpers::TaskTest;
use tributary_sdk::{
  ReadWrite as _, Evidence, tendermint::tx::TendermintTx, Transaction as TributaryTransaction,
  BlockHeader, Block, Tributary,
};
use serai_tributary_types::{TributaryValidator, TributaryValidatorSet};
use serai_coordinator_substrate::test_helpers::random_tributary_validator_set_info;
use super::*;

/// Create a Tributary with a single validator.
///
/// This returns the Tributary (kept alive so the Tendermint machine keeps running) and the
/// validator's signing key.
async fn make_tributary(
  db: MemDb,
  weights: &[u16],
) -> (TributaryValidatorSetInfo, Tributary<MemDb, Transaction, NopP2p>) {
  let mut rng = new_test_rng();
  let mut key = None;
  let mut validator_keys = vec![];
  let mut tributary_validators = vec![];
  for weight in weights.iter().copied() {
    let this_key = random_key(&mut rng);
    let pub_key = <Ristretto as WrappedGroup>::generator() * *this_key;
    key = Some(this_key);
    validator_keys.push((pub_key, u64::from(weight)));
    // Build a TributaryValidator matching the generated key
    tributary_validators.push(TributaryValidator::new(
      pub_key.to_bytes(),
      pub_key.to_bytes(),
      pub_key.to_bytes().to_vec(),
      weight,
    ));
  }
  let tributary_validator_set = TributaryValidatorSet::new(tributary_validators);
  let tributary_validator_set_info =
    random_tributary_validator_set_info(&mut rng, tributary_validator_set);
  let tributary = Tributary::<MemDb, Transaction, NopP2p>::new(
    db,
    tributary_validator_set_info.tributary_genesis(),
    // Use a past start_time so TendermintMachine::new doesn't sleep waiting for block end time
    1,
    key.unwrap(),
    validator_keys,
    NopP2p,
  )
  .await
  .expect("Tributary::new returned `None`?");
  (tributary_validator_set_info, tributary)
}

#[tokio::test]
async fn new_scan_tributary_task() {
  // Single validator with weight > 1
  {
    let db = MemDb::new();
    let (set_info, tributary) = make_tributary(db.clone(), &[3]).await;

    let task =
      ScanTributaryTask::<MemDb, NopP2p>::new(db.clone(), set_info.clone(), tributary.reader());

    assert_eq!(task.set.set, set_info.set);
    assert_eq!(task.set.tributary_validator_set.consensus_tributary_validators.len(), 1);
    assert_eq!(
      task.set.tributary_validator_set.consensus_tributary_validators[0].networks_substrate_key,
      set_info.tributary_validator_set.consensus_tributary_validators[0].networks_substrate_key
    );
    assert_eq!(task.set.tributary_validator_set.total_weight(), 3);
  }

  // Multiple validators with different weights
  {
    let db = MemDb::new();
    let (set_info, tributary) = make_tributary(db.clone(), &[1, 2, 4]).await;
    let task =
      ScanTributaryTask::<MemDb, NopP2p>::new(db.clone(), set_info.clone(), tributary.reader());

    assert_eq!(task.set.set, set_info.set);
    assert_eq!(task.set.tributary_validator_set.consensus_tributary_validators.len(), 3);
    assert_eq!(task.set.tributary_validator_set.total_weight(), 7);
    assert_eq!(task.set.tributary_validator_set.consensus_tributary_validators[0].weight, 1);
    assert_eq!(task.set.tributary_validator_set.consensus_tributary_validators[1].weight, 2);
    assert_eq!(task.set.tributary_validator_set.consensus_tributary_validators[2].weight, 4);
  }
}

/// Wait until `block_after(parent)` returns `Some`, with a 30s timeout.
async fn wait_for_block_after(
  tributary: &Tributary<MemDb, Transaction, NopP2p>,
  parent: &[u8; 32],
) -> [u8; 32] {
  let reader = tributary.reader();
  let start = Instant::now();
  loop {
    if let Some(hash) = reader.block_after(parent) {
      return hash;
    }
    assert!(
      start.elapsed() <= Duration::from_secs(30),
      "timed out waiting for a block after {parent:?}"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
  }
}

/// Write a fake block into the DB so the TributaryReader can find it.
///
/// Returns the block's hash.
fn inject_block(
  mut txn: impl DbTxn,
  genesis: [u8; 32],
  parent: [u8; 32],
  transactions: Vec<TributaryTransaction<Transaction>>,
) -> [u8; 32] {
  let tx_hashes: Vec<[u8; 32]> =
    transactions.iter().map(tributary_sdk::Transaction::hash).collect();
  let txs_hash =
    Blake2s256::digest(tx_hashes.iter().flat_map(|h| h.iter().copied()).collect::<Vec<_>>()).into();
  let block = Block { header: BlockHeader { parent, transactions: txs_hash }, transactions };
  let block_hash = block.hash();
  let serialized = block.serialize();

  let block_after_key = MemDb::key(
    b"tributary_blockchain",
    b"block_after",
    [genesis.as_ref(), parent.as_ref()].concat(),
  );
  let block_key =
    MemDb::key(b"tributary_blockchain", b"block", [genesis.as_ref(), block_hash.as_ref()].concat());

  txn.put(block_after_key, block_hash);
  txn.put(block_key, serialized);
  txn.commit();

  block_hash
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_tributary_task_run_iteration() {
  let mut rng = new_test_rng();
  // No blocks committed yet: returns false
  {
    let db = MemDb::new();
    let (set_info, tributary) = make_tributary(db.clone(), &[1]).await;

    let mut task = ScanTributaryTask::<MemDb, NopP2p>::new(db, set_info, tributary.reader());
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
  }

  {
    let mut db = MemDb::new();
    let (tributary_validator_set_info, tributary) = make_tributary(db.clone(), &[1]).await;
    let genesis = tributary_validator_set_info.tributary_genesis();

    // Wait for at least one real committed block
    wait_for_block_after(&tributary, &genesis).await;

    // Create one task that persists across the remaining steps so each run_iteration
    // continues from where the previous one left off.
    let mut task = ScanTributaryTask::<MemDb, NopP2p>::new(
      db.clone(),
      tributary_validator_set_info.clone(),
      tributary.reader(),
    );

    // Processes committed block(s) and records progress
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    let (last_handled_block_number, last_handled_block_hash) =
      TributaryDb::last_handled_tributary_block(&db, tributary_validator_set_info.set).unwrap();
    assert!(last_handled_block_number >= 1, "expected at least block 1 to be handled");

    // Processes block with provided and signed txs - inject after the actual last handled block
    let batch_tx =
      TributaryTransaction::Application(Transaction::Batch { hash: random_bytes(&mut rng) });
    let fake_evidence = TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(
      Evidence::InvalidPrecommit(make_signed_message_bytes(
        tributary_validator_set_info.tributary_validator_set.consensus_tributary_validators[0]
          .networks_substrate_key,
      )),
    ));
    let block_txs = vec![fake_evidence, batch_tx];

    let local_qty_key =
      MemDb::key(b"tributary_provided", b"local_quantity", [genesis.as_ref(), b"Batch"].concat());
    let block_hash = inject_block(db.txn(), genesis, last_handled_block_hash, block_txs.clone());
    let block_qty_key = MemDb::key(
      b"tributary_provided",
      b"block_quantity",
      [genesis.as_ref(), block_hash.as_ref(), b"Batch"].concat(),
    );
    {
      let mut txn = db.txn();
      txn.put(&local_qty_key, 1u32.to_le_bytes());
      txn.put(block_qty_key, 1u32.to_le_bytes());
      txn.commit();
    }

    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    let mut txn = db.txn();
    assert_block_side_effects(&mut txn, tributary_validator_set_info.set, &block_txs);
  }

  // Errors when locally provided txs are missing
  {
    let mut db = MemDb::new();
    let (set_info, tributary) = make_tributary(db.clone(), &[1]).await;
    let genesis = set_info.tributary_genesis();

    let cosign_tx = Transaction::Cosign { substrate_block_hash: random_block_hash(&mut rng) };
    tributary.provide_transaction(cosign_tx).await.unwrap();

    // Wait for a block that includes the provided transaction
    let reader = tributary.reader();
    let mut parent = genesis;
    let start = Instant::now();
    loop {
      assert!(
        start.elapsed() <= Duration::from_secs(30),
        "timed out waiting for a block with the provided tx"
      );
      if let Some(hash) = reader.block_after(&parent) {
        let block = reader.block(&hash).unwrap();
        if block
          .transactions
          .iter()
          .any(|tx| matches!(tx.kind(), tributary_sdk::transaction::TransactionKind::Provided(_)))
        {
          break;
        }
        parent = hash;
      } else {
        tokio::time::sleep(Duration::from_millis(100)).await;
      }
    }

    // Delete the locally_provided_quantity to trigger the error
    let local_qty_key =
      MemDb::key(b"tributary_provided", b"local_quantity", [genesis.as_ref(), b"Cosign"].concat());
    let mut txn = db.txn();
    txn.del(local_qty_key);
    txn.commit();

    let mut task = ScanTributaryTask::<MemDb, NopP2p>::new(db, set_info, reader);
    TaskTest::task_runs_and_fails_with(&mut task, "didn't have the provided Transactions").await;
  }
}
