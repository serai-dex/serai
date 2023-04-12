use std::collections::HashMap;

use zeroize::Zeroizing;
use rand_core::{RngCore, OsRng};

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use crate::{
  Transaction, Mempool,
  tests::{SignedTransaction, signed_transaction},
};

fn new_mempool<T: Transaction>() -> ([u8; 32], Mempool<T>) {
  let mut genesis = [0; 32];
  OsRng.fill_bytes(&mut genesis);
  (genesis, Mempool::new(genesis))
}

#[test]
fn mempool_addition() {
  let (genesis, mut mempool) = new_mempool::<SignedTransaction>();

  let key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));

  let first_tx = signed_transaction(&mut OsRng, genesis, &key, 0);
  let signer = first_tx.1.signer;
  assert_eq!(mempool.next_nonce(&signer), None);

  // Add TX 0
  assert!(mempool.add(&HashMap::new(), first_tx.clone()));
  assert_eq!(mempool.next_nonce(&signer), Some(1));

  // Adding it again should fail
  assert!(!mempool.add(&HashMap::new(), first_tx.clone()));

  // Do the same with the next nonce
  let second_tx = signed_transaction(&mut OsRng, genesis, &key, 1);
  assert!(mempool.add(&HashMap::new(), second_tx.clone()));
  assert_eq!(mempool.next_nonce(&signer), Some(2));
  assert!(!mempool.add(&HashMap::new(), second_tx.clone()));

  // If the mempool doesn't have a nonce for an account, it should successfully use the
  // blockchain's
  let second_key = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
  let tx = signed_transaction(&mut OsRng, genesis, &second_key, 2);
  let second_signer = tx.1.signer;
  assert_eq!(mempool.next_nonce(&second_signer), None);
  let mut blockchain_nonces = HashMap::from([(second_signer, 2)]);
  assert!(mempool.add(&blockchain_nonces, tx.clone()));
  assert_eq!(mempool.next_nonce(&second_signer), Some(3));

  // Getting a block should work
  let block = mempool.block(&HashMap::new());
  assert_eq!(block, mempool.block(&blockchain_nonces));
  assert_eq!(block.len(), 3);

  // If the blockchain says an account had its nonce updated, it should cause a prune
  blockchain_nonces.insert(signer, 1);
  let block = mempool.block(&blockchain_nonces);
  assert_eq!(block.len(), 2);
  assert!(!block.contains_key(&first_tx.hash()));
  assert_eq!(mempool.txs(), &block);

  // Removing should also successfully prune
  mempool.remove(&tx.hash());
  assert_eq!(mempool.txs(), &HashMap::from([(second_tx.hash(), second_tx)]));
}
