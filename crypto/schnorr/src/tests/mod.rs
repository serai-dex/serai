use core::ops::Deref;

use zeroize::Zeroizing;
use rand_core::OsRng;

use sha2::Sha256;

use group::{ff::Field, Group};
use multiexp::BatchVerifier;

use ciphersuite::{Ciphersuite, Ed25519};

use crate::{
  SchnorrSignature,
  aggregate::{SchnorrAggregator, SchnorrAggregate},
};

mod rfc8032;

pub(crate) fn sign<C: Ciphersuite>() {
  let private_key = Zeroizing::new(C::random_nonzero_F(&mut OsRng));
  let nonce = Zeroizing::new(C::random_nonzero_F(&mut OsRng));
  let challenge = C::random_nonzero_F(&mut OsRng); // Doesn't bother to craft an HRAm
  assert!(SchnorrSignature::<C>::sign(&private_key, nonce, challenge)
    .verify(C::generator() * private_key.deref(), challenge));
}

// The above sign function verifies signing works
// This verifies invalid signatures don't pass, using zero signatures, which should effectively be
// random
pub(crate) fn verify<C: Ciphersuite>() {
  assert!(!SchnorrSignature::<C> { R: C::G::identity(), s: C::F::zero() }
    .verify(C::generator() * C::random_nonzero_F(&mut OsRng), C::random_nonzero_F(&mut OsRng)));
}

pub(crate) fn batch_verify<C: Ciphersuite>() {
  // Create 5 signatures
  let mut keys = vec![];
  let mut challenges = vec![];
  let mut sigs = vec![];
  for i in 0 .. 5 {
    keys.push(Zeroizing::new(C::random_nonzero_F(&mut OsRng)));
    challenges.push(C::random_nonzero_F(&mut OsRng));
    sigs.push(SchnorrSignature::<C>::sign(
      &keys[i],
      Zeroizing::new(C::random_nonzero_F(&mut OsRng)),
      challenges[i],
    ));
  }

  // Batch verify
  {
    let mut batch = BatchVerifier::new(5);
    for (i, sig) in sigs.iter().enumerate() {
      sig.batch_verify(&mut OsRng, &mut batch, i, C::generator() * keys[i].deref(), challenges[i]);
    }
    batch.verify_vartime_with_vartime_blame().unwrap();
  }

  // Shift 1 from s from one to another and verify it fails
  // This test will fail if unique factors aren't used per-signature, hence its inclusion
  {
    let mut batch = BatchVerifier::new(5);
    for (i, mut sig) in sigs.clone().drain(..).enumerate() {
      if i == 1 {
        sig.s += C::F::one();
      }
      if i == 2 {
        sig.s -= C::F::one();
      }
      sig.batch_verify(&mut OsRng, &mut batch, i, C::generator() * keys[i].deref(), challenges[i]);
    }
    if let Err(blame) = batch.verify_vartime_with_vartime_blame() {
      assert!((blame == 1) || (blame == 2));
    } else {
      panic!("Batch verification considered malleated signatures valid");
    }
  }
}

pub(crate) fn aggregate<C: Ciphersuite>() {
  // Create 5 signatures
  let mut keys = vec![];
  let mut challenges = vec![];
  let mut aggregator = SchnorrAggregator::<Sha256, C>::new();
  for i in 0 .. 5 {
    keys.push(Zeroizing::new(C::random_nonzero_F(&mut OsRng)));
    challenges.push(C::random_nonzero_F(&mut OsRng));
    aggregator.aggregate(
      C::generator() * keys[i].deref(),
      challenges[i],
      SchnorrSignature::<C>::sign(
        &keys[i],
        Zeroizing::new(C::random_nonzero_F(&mut OsRng)),
        challenges[i],
      ),
    );
  }

  let aggregate = aggregator.complete().unwrap();
  let aggregate =
    SchnorrAggregate::<C>::read::<&[u8]>(&mut aggregate.serialize().as_ref()).unwrap();
  assert!(aggregate.verify::<Sha256>(
    keys
      .iter()
      .map(|key| C::generator() * key.deref())
      .zip(challenges.iter().cloned())
      .collect::<Vec<_>>()
      .as_ref()
  ));
}

#[test]
fn test() {
  sign::<Ed25519>();
  verify::<Ed25519>();
  batch_verify::<Ed25519>();
  aggregate::<Ed25519>();
}
