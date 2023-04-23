use core::time::Duration;

use zeroize::Zeroizing;

use rand_core::{RngCore, OsRng};

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};
use schnorr::SchnorrSignature;

use tokio::time::sleep;

use serai_db::MemDb;

use tributary::{Signed, Transaction as TransactionTrait, Tributary};

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
  let pub_key = Ristretto::generator() * *key;

  let attempt = 0;
  let mut commitments = vec![0; 256];
  OsRng.fill_bytes(&mut commitments);

  // Create the TX with a null signature so we can get its sig hash
  let tx = Transaction::DkgCommitments(
    attempt,
    commitments.clone(),
    Signed {
      signer: pub_key,
      nonce: 0,
      signature: SchnorrSignature::<Ristretto> {
        R: Ristretto::generator(),
        s: <Ristretto as Ciphersuite>::F::ZERO,
      },
    },
  );

  // Re-create it with the actual signature
  // We could mutate the existing one, we'd just have to match to the DkgCommitments enum variant
  let tx = Transaction::DkgCommitments(
    attempt,
    commitments,
    Signed {
      signer: pub_key,
      nonce: 0,
      signature: SchnorrSignature::<Ristretto>::sign(
        &key,
        Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng)),
        tx.sig_hash(spec.genesis()),
      ),
    },
  );

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
