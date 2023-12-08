use core::time::Duration;

use rand_core::{RngCore, OsRng};

use tokio::time::sleep;

use serai_db::MemDb;

use tributary::{
  transaction::Transaction as TransactionTrait, Transaction as TributaryTransaction, Tributary,
};

use crate::{
  tributary::Transaction,
  tests::{
    LocalP2p,
    tributary::{new_keys, new_spec, new_tributaries, run_tributaries, wait_for_tx_inclusion},
  },
};

#[tokio::test]
async fn tx_test() {
  let keys = new_keys(&mut OsRng);
  let spec = new_spec(&mut OsRng, &keys);

  let tributaries = new_tributaries(&keys, &spec)
    .await
    .into_iter()
    .map(|(_, p2p, tributary)| (p2p, tributary))
    .collect::<Vec<_>>();

  // Run the tributaries in the background
  tokio::spawn(run_tributaries(tributaries.clone()));

  // Send a TX from a random Tributary
  let sender =
    usize::try_from(OsRng.next_u64() % u64::try_from(tributaries.len()).unwrap()).unwrap();
  let key = keys[sender].clone();

  let attempt = 0;
  let mut commitments = vec![0; 256];
  OsRng.fill_bytes(&mut commitments);

  // Create the TX with a null signature so we can get its sig hash
  let block_before_tx = tributaries[sender].1.tip().await;
  let mut tx =
    Transaction::DkgCommitments(attempt, vec![commitments.clone()], Transaction::empty_signed());
  tx.sign(&mut OsRng, spec.genesis(), &key);

  assert_eq!(tributaries[sender].1.add_transaction(tx.clone()).await, Ok(true));
  let included_in = wait_for_tx_inclusion(&tributaries[sender].1, block_before_tx, tx.hash()).await;
  // Also sleep for the block time to ensure the block is synced around before we run checks on it
  sleep(Duration::from_secs(Tributary::<MemDb, Transaction, LocalP2p>::block_time().into())).await;

  // All tributaries should have acknowledged this transaction in a block
  for (_, tributary) in tributaries {
    let block = tributary.reader().block(&included_in).unwrap();
    assert_eq!(block.transactions, vec![TributaryTransaction::Application(tx.clone())]);
  }
}
