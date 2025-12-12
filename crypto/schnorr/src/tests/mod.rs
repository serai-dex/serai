use core::ops::Deref;
use std_shims::prelude::*;

use zeroize::Zeroizing;
use rand_core::OsRng;

use dalek_ff_group::Ed25519;
use ciphersuite::{
  group::{ff::Field, Group},
  GroupIo, WithPreferredHash,
};
use multiexp::BatchVerifier;

use crate::SchnorrSignature;
#[cfg(feature = "aggregate")]
use crate::aggregate::{SchnorrAggregator, SchnorrAggregate};

mod rfc8032;

pub(crate) fn sign<C: GroupIo>() {
  let private_key = Zeroizing::new(C::F::random(&mut OsRng));
  let nonce = Zeroizing::new(C::F::random(&mut OsRng));
  let challenge = C::F::random(&mut OsRng); // Doesn't bother to craft an HRAm
  assert!(SchnorrSignature::<C>::sign(&private_key, nonce, challenge)
    .verify(C::generator() * private_key.deref(), challenge));
}

// The above sign function verifies signing works
// This verifies invalid signatures don't pass, using zero signatures, which should effectively be
// random
pub(crate) fn verify<C: GroupIo>() {
  assert!(!SchnorrSignature::<C> { R: C::G::identity(), s: C::F::ZERO }
    .verify(C::generator() * C::F::random(&mut OsRng), C::F::random(&mut OsRng)));
}

pub(crate) fn batch_verify<C: GroupIo>() {
  // Create 5 signatures
  let mut keys = vec![];
  let mut challenges = vec![];
  let mut sigs = vec![];
  for i in 0 .. 5 {
    keys.push(Zeroizing::new(C::F::random(&mut OsRng)));
    challenges.push(C::F::random(&mut OsRng));
    sigs.push(SchnorrSignature::<C>::sign(
      &keys[i],
      Zeroizing::new(C::F::random(&mut OsRng)),
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
        sig.s += C::F::ONE;
      }
      if i == 2 {
        sig.s -= C::F::ONE;
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

#[cfg(feature = "aggregate")]
pub(crate) fn aggregate<C: GroupIo + WithPreferredHash>() {
  const DST: &[u8] = b"Schnorr Aggregator Test";

  // Create 5 signatures
  let mut keys = vec![];
  let mut challenges = vec![];
  let mut aggregator = SchnorrAggregator::<C>::new(DST);
  for i in 0 .. 5 {
    keys.push(Zeroizing::new(C::F::random(&mut OsRng)));
    // In practice, this MUST be a secure challenge binding to the nonce, key, and any message
    challenges.push(C::F::random(&mut OsRng));
    aggregator.aggregate(
      challenges[i],
      SchnorrSignature::<C>::sign(
        &keys[i],
        Zeroizing::new(C::F::random(&mut OsRng)),
        challenges[i],
      ),
    );
  }

  let aggregate = aggregator.complete().unwrap();
  let aggregate =
    SchnorrAggregate::<C>::read::<&[u8]>(&mut aggregate.serialize().as_ref()).unwrap();
  assert!(aggregate.verify(
    DST,
    keys
      .iter()
      .map(|key| C::generator() * key.deref())
      .zip(challenges.iter().copied())
      .collect::<Vec<_>>()
      .as_ref(),
  ));
}

#[test]
fn test() {
  sign::<Ed25519>();
  verify::<Ed25519>();
  batch_verify::<Ed25519>();
  #[cfg(feature = "aggregate")]
  aggregate::<Ed25519>();
}
