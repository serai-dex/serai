use rand::rngs::OsRng;

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

use crate::{
  random_scalar,
  ringct::hash_to_point::{hash_to_point as c_hash_to_point, rust_hash_to_point},
};

#[test]
fn hash_to_point() {
  for _ in 0 .. 50 {
    let point = &random_scalar(&mut OsRng) * &ED25519_BASEPOINT_TABLE;
    assert_eq!(rust_hash_to_point(point), c_hash_to_point(point));
  }
}
