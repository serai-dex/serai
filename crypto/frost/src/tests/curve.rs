use rand_core::{RngCore, CryptoRng};

use crate::{
  Curve, MultisigKeys,
  tests::{schnorr::{sign, verify, batch_verify}, key_gen}
};

// Test generation of FROST keys
fn key_generation<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  // This alone verifies the verification shares and group key are agreed upon as expected
  key_gen::<_, C>(rng);
}

// Test serialization of generated keys
fn keys_serialization<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  for (_, keys) in key_gen::<_, C>(rng) {
    assert_eq!(&MultisigKeys::<C>::deserialize(&keys.serialize()).unwrap(), &*keys);
  }
}

pub fn test_curve<R: RngCore + CryptoRng, C: Curve>(rng: &mut R) {
  // TODO: Test the Curve functions themselves

  // Test Schnorr signatures work as expected
  sign::<_, C>(rng);
  verify::<_, C>(rng);
  batch_verify::<_, C>(rng);

  // Test FROST key generation and serialization of MultisigKeys works as expected
  key_generation::<_, C>(rng);
  keys_serialization::<_, C>(rng);
}
