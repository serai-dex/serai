use rand_core::OsRng;

use ciphersuite::Ed448;

use crate::tests::{key_gen, promote::test_generator_promotion};

#[test]
fn ed448() {
  key_gen::<_, Ed448>(&mut OsRng);
  test_generator_promotion::<_, Ed448>(&mut OsRng);
}
