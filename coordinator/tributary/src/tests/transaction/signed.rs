use std::collections::{HashSet, HashMap};

use rand::rngs::OsRng;

use blake2::{Digest, Blake2s256};

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};

use crate::{
  ReadWrite, Signed, Transaction, verify_transaction,
  tests::{random_signed, random_signed_transaction},
};

#[test]
fn serialize_signed() {
  let signed = random_signed(&mut rand::rngs::OsRng);
  assert_eq!(Signed::read::<&[u8]>(&mut signed.serialize().as_ref()).unwrap(), signed);
}

#[test]
fn sig_hash() {
  let (genesis, tx1) = random_signed_transaction(&mut OsRng);
  assert!(tx1.sig_hash(genesis) != tx1.sig_hash(Blake2s256::digest(genesis).into()));

  let (_, tx2) = random_signed_transaction(&mut OsRng);
  assert!(tx1.hash() != tx2.hash());
  assert!(tx1.sig_hash(genesis) != tx2.sig_hash(genesis));
}

#[test]
fn signed_transaction() {
  let (genesis, tx) = random_signed_transaction(&mut OsRng);

  // Mutate various properties and verify it no longer works

  // Different genesis
  assert!(verify_transaction(
    &tx,
    Blake2s256::digest(genesis).into(),
    &mut HashSet::new(),
    &mut HashMap::from([(tx.1.signer, tx.1.nonce)]),
  )
  .is_err());

  // Different data
  {
    let mut tx = tx.clone();
    tx.0 = Blake2s256::digest(tx.0).to_vec();
    assert!(verify_transaction(
      &tx,
      genesis,
      &mut HashSet::new(),
      &mut HashMap::from([(tx.1.signer, tx.1.nonce)]),
    )
    .is_err());
  }

  // Different signer
  {
    let mut tx = tx.clone();
    tx.1.signer += Ristretto::generator();
    assert!(verify_transaction(
      &tx,
      genesis,
      &mut HashSet::new(),
      &mut HashMap::from([(tx.1.signer, tx.1.nonce)]),
    )
    .is_err());
  }

  // Different nonce
  {
    #[allow(clippy::redundant_clone)] // False positive?
    let mut tx = tx.clone();
    tx.1.nonce = tx.1.nonce.wrapping_add(1);
    assert!(verify_transaction(
      &tx,
      genesis,
      &mut HashSet::new(),
      &mut HashMap::from([(tx.1.signer, tx.1.nonce)]),
    )
    .is_err());
  }

  // Different signature
  {
    let mut tx = tx.clone();
    tx.1.signature.R += Ristretto::generator();
    assert!(verify_transaction(
      &tx,
      genesis,
      &mut HashSet::new(),
      &mut HashMap::from([(tx.1.signer, tx.1.nonce)]),
    )
    .is_err());
  }
  {
    let mut tx = tx.clone();
    tx.1.signature.s += <Ristretto as Ciphersuite>::F::ONE;
    assert!(verify_transaction(
      &tx,
      genesis,
      &mut HashSet::new(),
      &mut HashMap::from([(tx.1.signer, tx.1.nonce)]),
    )
    .is_err());
  }

  // Sanity check the original TX was never mutated and is valid
  let mut nonces = HashMap::from([(tx.1.signer, tx.1.nonce)]);
  verify_transaction(&tx, genesis, &mut HashSet::new(), &mut nonces).unwrap();
  assert_eq!(nonces, HashMap::from([(tx.1.signer, tx.1.nonce.wrapping_add(1))]));
}

#[test]
fn invalid_nonce() {
  let (genesis, tx) = random_signed_transaction(&mut OsRng);

  assert!(verify_transaction(
    &tx,
    genesis,
    &mut HashSet::new(),
    &mut HashMap::from([(tx.1.signer, tx.1.nonce.wrapping_add(1))]),
  )
  .is_err());
}
