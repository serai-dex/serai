use rand_core::OsRng;

use group::{ff::Field, Group};

use multiexp::BatchVerifier;

use ciphersuite::{Ciphersuite, Ristretto};
use crate::SchnorrSignature;

pub(crate) fn core_sign<C: Ciphersuite>() {
  let private_key = C::random_nonzero_F(&mut OsRng);
  let nonce = C::random_nonzero_F(&mut OsRng);
  let challenge = C::random_nonzero_F(&mut OsRng); // Doesn't bother to craft an HRAm
  assert!(SchnorrSignature::sign::<C>(private_key, nonce, challenge)
    .verify(C::generator() * private_key, challenge));
}

// The above sign function verifies signing works
// This verifies invalid signatures don't pass, using zero signatures, which should effectively be
// random
pub(crate) fn core_verify<C: Ciphersuite>() {
  assert!(!SchnorrSignature { R: C::G::identity(), s: C::F::zero() }
    .verify(C::generator() * C::random_nonzero_F(&mut OsRng), C::random_nonzero_F(&mut OsRng)));
}

pub(crate) fn core_batch_verify<C: Ciphersuite>() {
  // Create 5 signatures
  let mut keys = vec![];
  let mut challenges = vec![];
  let mut sigs = vec![];
  for i in 0 .. 5 {
    keys.push(C::random_nonzero_F(&mut OsRng));
    challenges.push(C::random_nonzero_F(&mut OsRng));
    sigs.push(SchnorrSignature::sign::<C>(keys[i], C::random_nonzero_F(&mut OsRng), challenges[i]));
  }

  // Batch verify
  {
    let mut batch = BatchVerifier::new(5);
    for (i, sig) in &sigs.enumerate() {
      sig.batch_verify(&mut OsRng, batch, i, C::generator() * keys[i], challenges[i]);
    }
    batch.verify_with_vartime_blame().unwrap();
  }

  // Shift 1 from s from one to another and verify it fails
  // This test will fail if unique factors aren't used per-signature, hence its inclusion
  {
    let mut batch = BatchVerifier::new(5);
    for (i, sig) in sigs.clone().drain(..).enumerate() {
      if i == 1 {
        sig.s += C::F::one();
      }
      if i == 2 {
        sig.s -= C::F::one();
      }
      sig.batch_verify(&mut OsRng, batch, i, C::generator() * keys[i], challenges[i]);
    }
    if let Err(blame) = batch.verify_with_vartime_blame() {
      assert!((blame == 1) || (blame == 2));
    } else {
      panic!("Batch verification considered malleated signatures valid");
    }
  }
}

#[test]
fn test() {
  core_sign::<Ristretto>();
  core_verify::<Ristretto>();
  core_batch_verify::<Ristretto>();
}
