use rand::rngs::OsRng;

use crate::tests::vectors::{Vectors, test_with_vectors};

#[cfg(feature = "secp256k1")]
use crate::curve::{Secp256k1, IetfSecp256k1Hram};

#[cfg(feature = "p256")]
use crate::curve::{P256, IetfP256Hram};

#[cfg(feature = "secp256k1")]
#[test]
fn secp256k1_vectors() {
  test_with_vectors::<_, Secp256k1, IetfSecp256k1Hram>(
    &mut OsRng,
    Vectors::from(
      serde_json::from_str::<serde_json::Value>(include_str!(
        "vectors/frost-secp256k1-sha256.json"
      ))
      .unwrap(),
    ),
  );
}

#[cfg(feature = "p256")]
#[test]
fn p256_vectors() {
  test_with_vectors::<_, P256, IetfP256Hram>(
    &mut OsRng,
    Vectors::from(
      serde_json::from_str::<serde_json::Value>(include_str!("vectors/frost-p256-sha256.json"))
        .unwrap(),
    ),
  );
}
