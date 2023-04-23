use core::time::Duration;

use rand_core::{RngCore, OsRng};

use tokio::time::sleep;

use serai_db::MemDb;

use tributary::Tributary;

use crate::{
  LocalP2p,
  tributary::Transaction,
  tests::tributary::{new_keys, new_spec, new_tributaries, run_tributaries},
};

#[tokio::test]
async fn tx_test() {
  let keys = new_keys(&mut OsRng);
  let spec = new_spec(&mut OsRng, &keys);

  let mut tributaries = new_tributaries(&keys, &spec).await;

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
  let mut tx =
    Transaction::DkgCommitments(attempt, commitments.clone(), Transaction::empty_signed());
  tx.sign(&mut OsRng, spec.genesis(), &key, 0);

  assert!(tributaries[sender].1.add_transaction(tx.clone()).await);
  // Sleep for two blocks
  sleep(Duration::from_secs((2 * Tributary::<MemDb, Transaction, LocalP2p>::block_time()).into()))
    .await;

  // All tributaries should have acknowledged this transaction in a block
  let mut included_in = None;
  for (_, tributary) in tributaries {
    if included_in.is_none() {
      let mut found = tributary.tip();

      let mut block;
      while {
        block = tributary.block(&found).unwrap();
        block.transactions.is_empty()
      } {
        found = block.parent();
      }

      included_in = Some(found);
    }

    let block = tributary.block(&included_in.unwrap()).unwrap();
    assert_eq!(block.transactions, vec![tx.clone()]);
  }
}
