use rand::rngs::OsRng;

use blake2::{Digest as _, Blake2s256};

use dalek_ff_group::Ristretto;
use ciphersuite::*;

use crate::{
  ReadWrite as _,
  transaction::{Signed, Transaction as _, verify_transaction},
  tests::{random_signed, random_signed_transaction},
};

#[test]
fn serialize_signed() {
  let signed = random_signed(&mut rand::rngs::OsRng);
  assert_eq!(Signed::read(signed.serialize().as_slice()).unwrap(), signed);
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
  assert!(verify_transaction(&tx, Blake2s256::digest(genesis).into(), &mut |_, _| Some(
    tx.1.nonce
  ))
  .is_err());

  // Different data
  {
    let mut tx = tx.clone();
    tx.0 = Blake2s256::digest(tx.0).to_vec();
    assert!(verify_transaction(&tx, genesis, &mut |_, _| Some(tx.1.nonce)).is_err());
  }

  // Different signer
  {
    let mut tx = tx.clone();
    tx.1.signer += Ristretto::generator();
    assert!(verify_transaction(&tx, genesis, &mut |_, _| Some(tx.1.nonce)).is_err());
  }

  // Different nonce
  {
    #[expect(clippy::redundant_clone)] // False positive?
    let mut tx = tx.clone();
    tx.1.nonce = tx.1.nonce.wrapping_add(1);
    assert!(verify_transaction(&tx, genesis, &mut |_, _| Some(tx.1.nonce)).is_err());
  }

  // Different signature
  {
    let mut tx = tx.clone();
    tx.1.signature.R += Ristretto::generator();
    assert!(verify_transaction(&tx, genesis, &mut |_, _| Some(tx.1.nonce)).is_err());
  }
  {
    let mut tx = tx.clone();
    tx.1.signature.s += <Ristretto as WrappedGroup>::F::ONE;
    assert!(verify_transaction(&tx, genesis, &mut |_, _| Some(tx.1.nonce)).is_err());
  }

  // Sanity check the original TX was never mutated and is valid
  verify_transaction(&tx, genesis, &mut |_, _| Some(tx.1.nonce)).unwrap();
}

#[test]
fn invalid_nonce() {
  let (genesis, tx) = random_signed_transaction(&mut OsRng);

  assert!(verify_transaction(&tx, genesis, &mut |_, _| Some(tx.1.nonce.wrapping_add(1)),).is_err());
}
