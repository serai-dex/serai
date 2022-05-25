use rand::rngs::OsRng;

use frost::tests::{curve::test_curve, key_gen};

use crate::frost::Ed25519;

#[test]
fn frost_ed25519() {
  test_curve::<_, Ed25519>(&mut OsRng);
  key_gen::<_, Ed25519>(&mut OsRng);
}
