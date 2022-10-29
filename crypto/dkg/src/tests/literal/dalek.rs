use rand_core::OsRng;

use crate::tests::{key_gen, promote::test_generator_promotion};

#[cfg(feature = "ristretto")]
#[test]
fn ristretto() {
  key_gen::<_, ciphersuite::Ristretto>(&mut OsRng);
  test_generator_promotion::<_, ciphersuite::Ristretto>(&mut OsRng);
}

#[cfg(feature = "ed25519")]
#[test]
fn ed25519() {
  key_gen::<_, ciphersuite::Ed25519>(&mut OsRng);
  test_generator_promotion::<_, ciphersuite::Ed25519>(&mut OsRng);
}
