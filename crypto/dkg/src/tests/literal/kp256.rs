use rand_core::OsRng;

use crate::tests::{key_gen, promote::test_generator_promotion};

#[cfg(feature = "secp256k1")]
#[test]
fn secp256k1() {
  key_gen::<_, ciphersuite::Secp256k1>(&mut OsRng);
  test_generator_promotion::<_, ciphersuite::Secp256k1>(&mut OsRng);
}

#[cfg(feature = "p256")]
#[test]
fn p256() {
  key_gen::<_, ciphersuite::P256>(&mut OsRng);
  test_generator_promotion::<_, ciphersuite::P256>(&mut OsRng);
}
