use blake2::{Digest as _, Blake2s256};

use serai_primitives::test_helpers::random_genesis;
use serai_task::test_helpers::TaskTest;
use tributary_sdk::{
  Tributary, ReadWrite as _, Block, BlockHeader, Transaction as TributaryTransaction, Evidence,
  tendermint::tx::TendermintTx,
};
use super::*;

/// Create a Tributary with a single validator. Returns the Tributary (kept alive so
/// the Tendermint machine keeps running) and the validator's signing key.
async fn make_tributary(
  db: MemDb,
) -> (Tributary<MemDb, Transaction, MockP2p>, Zeroizing<<Ristretto as WrappedGroup>::F>, [u8; 32]) {
  let key = random_key(&mut OsRng);
  let pub_key = get_key_point(&key);
  let genesis = random_genesis(&mut OsRng);
  let tributary = Tributary::<MemDb, Transaction, MockP2p>::new(
    db,
    genesis,
    // Use a past start_time so TendermintMachine::new doesn't sleep waiting for block end time
    1,
    key.clone(),
    vec![(pub_key, 1)],
    MockP2p,
  )
  .await
  .expect("Tributary::new returned None");
  (tributary, key, genesis)
}

#[tokio::test]
async fn new_scan_tributary_task() {
  let db = MemDb::new();
  let (tributary, _, _) = make_tributary(db.clone()).await;

  // Single validator with weight > 1
  {
    let (_, addr) = random_serai_address_and_key(&mut OsRng);
    let set_info = new_test_set_info(&[(addr, 3)]);
    let task = ScanTributaryTask::<MemDb, MockP2p>::new(db.clone(), set_info, tributary.reader());

    assert_eq!(task.validators.len(), 1);
    assert_eq!(task.validators[0], addr);
    assert_eq!(task.total_weight, 3);
    assert_eq!(task.validator_weights[&addr], 3);
  }

  // Multiple validators with different weights
  {
    let (_, addr1) = random_serai_address_and_key(&mut OsRng);
    let (_, addr2) = random_serai_address_and_key(&mut OsRng);
    let (_, addr3) = random_serai_address_and_key(&mut OsRng);
    let set_info = new_test_set_info(&[(addr1, 1), (addr2, 2), (addr3, 4)]);
    let task = ScanTributaryTask::<MemDb, MockP2p>::new(db.clone(), set_info, tributary.reader());

    assert_eq!(task.validators.len(), 3);
    assert_eq!(task.total_weight, 7);
    assert_eq!(task.validator_weights[&addr1], 1);
    assert_eq!(task.validator_weights[&addr2], 2);
    assert_eq!(task.validator_weights[&addr3], 4);
  }

  // Preserves set info
  {
    let (_, addr) = random_serai_address_and_key(&mut OsRng);
    let set_info = new_test_set_info(&[(addr, 1)]);
    let expected_set = set_info.set;
    let task = ScanTributaryTask::<MemDb, MockP2p>::new(db.clone(), set_info, tributary.reader());

    assert_eq!(task.set.set, expected_set);
  }
}

/// Wait until `block_after(parent)` returns `Some`, with a 30s timeout.
async fn wait_for_block_after(
  tributary: &Tributary<MemDb, Transaction, MockP2p>,
  parent: &[u8; 32],
) -> [u8; 32] {
  let reader = tributary.reader();
  let start = std::time::Instant::now();
  loop {
    if let Some(hash) = reader.block_after(parent) {
      return hash;
    }
    assert!(
      start.elapsed() <= std::time::Duration::from_secs(30),
      "timed out waiting for a block after {parent:?}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
  }
}

/// Write a fake block into the DB so the TributaryReader can find it.
/// Returns the block's hash.
fn inject_block(
  mut txn: impl DbTxn,
  genesis: [u8; 32],
  parent: [u8; 32],
  transactions: Vec<TributaryTransaction<Transaction>>,
) -> [u8; 32] {
  let tx_hashes: Vec<[u8; 32]> = transactions.iter().map(tributary_sdk::Transaction::hash).collect();
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
  let (_, addr) = random_serai_address_and_key(&mut OsRng);
  let set_info = new_test_set_info(&[(addr, 1)]);

  // No blocks committed yet: returns false
  {
    let db = MemDb::new();
    let (tributary, _, _) = make_tributary(db.clone()).await;

    let mut task =
      ScanTributaryTask::<MemDb, MockP2p>::new(db, set_info.clone(), tributary.reader());
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
  }

  let mut db = MemDb::new();
  let (tributary, _, genesis) = make_tributary(db.clone()).await;

  // Wait for at least one real committed block
  wait_for_block_after(&tributary, &genesis).await;

  // Create one task that persists across the remaining steps so each run_iteration
  // continues from where the previous one left off.
  let mut task =
    ScanTributaryTask::<MemDb, MockP2p>::new(db.clone(), set_info.clone(), tributary.reader());

  // Processes committed block(s) and records progress
  TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

  let (last_handled_block_number, last_handled_block_hash) =
    TributaryDb::last_handled_tributary_block(&db, default_test_validator_set()).unwrap();
  assert!(last_handled_block_number >= 1, "expected at least block 1 to be handled");

  // Processes block with provided and signed txs - inject after the actual last handled block
  {
    let batch_tx =
      TributaryTransaction::Application(Transaction::Batch { hash: random_bytes_32(&mut OsRng) });
    let fake_evidence = TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(
      Evidence::InvalidPrecommit(make_signed_message_bytes(addr.0)),
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
    assert_block_side_effects(&mut txn, default_test_validator_set(), &block_txs);
  }

  // Errors when locally provided txs are missing
  {
    let mut db2 = MemDb::new();
    let (tributary2, _, genesis2) = make_tributary(db2.clone()).await;

    let cosign_tx = Transaction::Cosign { substrate_block_hash: random_block_hash(&mut OsRng) };
    tributary2.provide_transaction(cosign_tx).await.unwrap();

    // Wait for a block that includes the provided transaction
    let reader = tributary2.reader();
    let mut parent = genesis2;
    let start = std::time::Instant::now();
    loop {
      assert!(
        start.elapsed() <= std::time::Duration::from_secs(30),
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
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
      }
    }

    // Delete the locally_provided_quantity to trigger the error
    let local_qty_key =
      MemDb::key(b"tributary_provided", b"local_quantity", [genesis2.as_ref(), b"Cosign"].concat());
    let mut txn = db2.txn();
    txn.del(local_qty_key);
    txn.commit();

    let set_info = new_test_set_info(&[(addr, 1)]);
    let mut task = ScanTributaryTask::<MemDb, MockP2p>::new(db2, set_info, reader);
    TaskTest::task_runs_and_fails_with(&mut task, "didn't have the provided Transactions").await;
  }
}
