use rand_core::{RngCore, CryptoRng};

use ff::Field;

use crate::{Curve, schnorr, algorithm::SchnorrSignature};

pub(crate) fn sign<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  let private_key = C::F::random(&mut *rng);
  let nonce = C::F::random(&mut *rng);
  let challenge = C::F::random(rng); // Doesn't bother to craft an HRAM
  assert!(
    schnorr::verify::<C>(
      C::generator_table() * private_key,
      challenge,
      &schnorr::sign(private_key, nonce, challenge)
    )
  );
}

// The above sign function verifies signing works
// This verifies invalid signatures don't pass, using zero signatures, which should effectively be
// random
pub(crate) fn verify<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  assert!(
    !schnorr::verify::<C>(
      C::generator_table() * C::F::random(&mut *rng),
      C::F::random(rng),
      &SchnorrSignature { R: C::generator_table() * C::F::zero(), s: C::F::zero() }
    )
  );
}

