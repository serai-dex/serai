use core::{num::NonZero, time::Duration};
use std::time::Instant;

use serai_primitives::test_helpers::random_bytes;
use serai_db::MemDb;
use serai_task::test_helpers::TaskTest;
use tributary_framework::{ReadWrite as _, Block, Tributary, TributaryHandle};
use super::*;

#[allow(non_snake_case)]
fn D_key(a: &'static str, b: &'static str, c: impl borsh::BorshSerialize) -> Vec<u8> {
  [
    [u8::try_from(a.len()).unwrap()].as_slice(),
    a.as_bytes(),
    [u8::try_from(b.len()).unwrap()].as_slice(),
    b.as_bytes(),
    borsh::to_vec(&c).unwrap().as_slice(),
  ]
  .concat()
}

struct NopNetwork;
impl<B: ::tendermint::Block>
  ::tendermint::Network<[u8; 32], [u8; 64], tributary_framework::AggregateSignature, B>
  for NopNetwork
{
  type Sleep = tokio::time::Sleep;
  fn sleep(duration: Duration) -> Self::Sleep {
    tokio::time::sleep(duration)
  }

  const LATENCY_TIME: Duration = Duration::from_secs(1);
  const BLOCK_DOWNLOADING_TIME: Duration = Duration::from_secs(1);
  const BLOCK_PROCESSING_TIME: Duration = Duration::from_secs(1);

  fn broadcast(
    &mut self,
    _genesis: impl AsRef<[u8]>,
    _message: ::tendermint::Message<[u8; 32], [u8; 64], tributary_framework::AggregateSignature, B>,
  ) -> impl Send + Future<Output = ()> {
    core::future::ready(())
  }
}

/// Create a Tributary with a single validator.
///
/// This returns the Tributary (kept alive so the Tendermint machine keeps running) and the
/// validator's signing key.
fn make_tributary(
  db: MemDb,
  weights: &[u16],
) -> (NewSetInformation, TributaryHandle<MemDb, Transaction>) {
  let mut key = None;
  let mut validator_keys = vec![];
  let mut validators = vec![];
  for weight in weights.iter().copied() {
    let this_key = random_key(&mut OsRng);
    let pub_key = <Ristretto as WrappedGroup>::generator() * *this_key;
    key = Some(this_key);
    validator_keys.push((pub_key, NonZero::new(weight).unwrap()));
    let addr = SeraiAddress(pub_key.to_bytes());
    validators.push((addr, weight));
  }
  let set_info = new_test_set_info(&validators);
  let (tributary, tributary_handle) = Tributary::<MemDb, Transaction, ()>::new(
    db,
    set_info.tributary_genesis(),
    None,
    validator_keys.into_iter().map(|(key, weight)| (key.to_bytes(), weight)).collect(),
    NopNetwork,
    (),
    key.unwrap(),
    100,
  )
  .expect("Tributary::new returned `Err(_)`?");
  tokio::spawn(tributary);
  (set_info, tributary_handle)
}

#[tokio::test]
async fn new_scan_tributary_task() {
  // Single validator with weight > 1
  {
    let db = MemDb::new();
    let (set_info, tributary) = make_tributary(db.clone(), &[3]);

    let task = ScanTributaryTask::<MemDb>::new(db.clone(), set_info.clone(), tributary);

    assert_eq!(task.set.set, set_info.set);
    assert_eq!(task.validators.len(), 1);
    assert_eq!(task.validators[0], set_info.validators[0].0);
    assert_eq!(task.total_weight, 3);
    assert_eq!(task.validator_weights.len(), 1);
    assert_eq!(task.validator_weights[&set_info.validators[0].0], 3);
  }

  // Multiple validators with different weights
  {
    let db = MemDb::new();
    let (set_info, tributary) = make_tributary(db.clone(), &[1, 2, 4]);
    let task = ScanTributaryTask::<MemDb>::new(db.clone(), set_info.clone(), tributary);

    assert_eq!(task.set.set, set_info.set);
    assert_eq!(task.validators.len(), 3);
    assert_eq!(task.total_weight, 7);
    assert_eq!(task.validator_weights.len(), 3);
    assert_eq!(task.validator_weights[&set_info.validators[0].0], 1);
    assert_eq!(task.validator_weights[&set_info.validators[1].0], 2);
    assert_eq!(task.validator_weights[&set_info.validators[2].0], 4);
  }
}

/// Wait until `block_after(parent)` returns `Some`, with a 30s timeout.
async fn wait_for_block_after(
  tributary: &TributaryHandle<MemDb, Transaction>,
  parent: &[u8; 32],
) -> [u8; 32] {
  let reader = tributary;
  let start = Instant::now();
  loop {
    if let Some(hash) = reader.block_after(*parent) {
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
  mut txn: impl Send + DbTxn,
  genesis: [u8; 32],
  parent: [u8; 32],
  transactions: Vec<Transaction>,
) -> [u8; 32] {
  let block = Block::instantiate(genesis, parent, 0, Box::default(), transactions.into()).unwrap();
  let block_hash = block.hash();
  let serialized = block.serialize();

  let block_after_key = D_key("TributaryBlockchain", "BlockAfter", (genesis, parent));
  let block_key = D_key("TributaryBlockchain", "Block", (genesis, block_hash));

  txn.set(block_after_key, block_hash);
  txn.set(block_key, serialized);
  txn.commit();

  block_hash
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_tributary_task_run_iteration() {
  // No blocks committed yet: returns false
  {
    let db = MemDb::new();
    let (set_info, tributary) = make_tributary(db.clone(), &[1]);

    let mut task = ScanTributaryTask::<MemDb>::new(db, set_info, tributary);
    TaskTest::task_runs_once_and_matches_progress(&mut task, false).await;
  }

  {
    let mut db = MemDb::new();
    let (set_info, tributary) = make_tributary(db.clone(), &[1]);
    let genesis = {
      let genesis_16 = set_info.tributary_genesis();
      let mut genesis = [0; 32];
      genesis[16 ..].copy_from_slice(&genesis_16);
      genesis
    };

    // Wait for at least one real committed block
    wait_for_block_after(&tributary, &genesis).await;

    // Create one task that persists across the remaining steps so each run_iteration
    // continues from where the previous one left off.
    let mut task = ScanTributaryTask::<MemDb>::new(db.clone(), set_info.clone(), tributary.clone());

    // Processes committed block(s) and records progress
    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    let (last_handled_block_number, last_handled_block_hash) =
      TributaryDb::last_handled_tributary_block(&db, set_info.set).unwrap();
    assert!(last_handled_block_number >= 1, "expected at least block 1 to be handled");

    // Processes block with provided and signed txs - inject after the actual last handled block
    let batch_tx = Transaction::Batch { hash: random_bytes(&mut OsRng) };
    /* TODO
    let fake_evidence = TributaryTransaction::Tendermint(Slash::SlashEvidence(
      Evidence::InvalidPrecommit(make_signed_message_bytes(set_info.validators[0].0 .0)),
    ));
    let block_txs = vec![fake_evidence, batch_tx];
    */
    let block_txs = vec![batch_tx.clone()];

    let local_qty_key =
      D_key("TributaryProvided", "LocallyProvided", (genesis, b"Batch".as_slice()));
    let local_tx_key =
      D_key("TributaryProvided", "LocallyProvidedHash", (genesis, b"Batch".as_slice(), 0u64));
    let _block_hash = inject_block(db.txn(), genesis, last_handled_block_hash, block_txs.clone());
    {
      let mut txn = db.txn();
      txn.set(&local_qty_key, 1u64.to_le_bytes());
      txn.set(&local_tx_key, batch_tx.hash());
      txn.commit();
    }
    assert_eq!(
      tributary.locally_provided_transactions("Batch", 0).collect::<Vec<_>>(),
      vec![batch_tx.hash()]
    );

    TaskTest::task_runs_once_and_matches_progress(&mut task, true).await;

    let mut txn = db.txn();
    assert_block_side_effects(&mut txn, set_info.set, &block_txs);
  }

  // Errors when locally provided txs are missing
  {
    let mut db = MemDb::new();
    let (set_info, tributary) = make_tributary(db.clone(), &[1]);
    let genesis = {
      let genesis_16 = set_info.tributary_genesis();
      let mut genesis = [0; 32];
      genesis[16 ..].copy_from_slice(&genesis_16);
      genesis
    };

    let cosign_tx = Transaction::Cosign { substrate_block_hash: random_block_hash(&mut OsRng) };
    tributary.transaction(cosign_tx).await.unwrap();

    // Wait for a block that includes the provided transaction
    let reader = tributary;
    let mut parent = genesis;
    let start = Instant::now();
    loop {
      assert!(
        start.elapsed() <= Duration::from_secs(90),
        "timed out waiting for a block with the provided tx"
      );
      if let Some(hash) = reader.block_after(parent) {
        let block = reader.block(hash).unwrap();
        if block.transactions().iter().any(|tx| {
          matches!(tx.kind(), tributary_framework::transaction::TransactionKind::Provided { .. })
        }) {
          break;
        }
        parent = hash;
      } else {
        tokio::time::sleep(Duration::from_millis(100)).await;
      }
    }

    let local_qty_key =
      D_key("TributaryProvided", "LocallyProvided", (genesis, b"Cosign".as_slice()));
    let mut txn = db.txn();
    txn.del(local_qty_key);
    txn.commit();

    let mut task = ScanTributaryTask::<MemDb>::new(db, set_info, reader);
    TaskTest::task_runs_and_fails_with(&mut task, "didn't have the provided Transactions").await;
  }
}
