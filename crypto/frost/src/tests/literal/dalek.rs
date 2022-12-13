use rand::rngs::OsRng;

use crate::{
  curve,
  tests::vectors::{Vectors, test_with_vectors},
};

#[cfg(feature = "ristretto")]
#[test]
fn ristretto_vectors() {
  test_with_vectors::<_, curve::Ristretto, curve::IetfRistrettoHram>(
    &mut OsRng,
    Vectors::from(
      serde_json::from_str::<serde_json::Value>(include_str!(
        "vectors/frost-ristretto255-sha512.json"
      ))
      .unwrap(),
    ),
  );
}

#[cfg(feature = "ed25519")]
#[test]
fn ed25519_vectors() {
  test_with_vectors::<_, curve::Ed25519, curve::IetfEd25519Hram>(
    &mut OsRng,
    Vectors::from(
      serde_json::from_str::<serde_json::Value>(include_str!("vectors/frost-ed25519-sha512.json"))
        .unwrap(),
    ),
  );
}
