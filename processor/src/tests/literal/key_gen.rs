use frost::curve::{Secp256k1, Ed25519};

use crate::tests::test_key_gen;

#[tokio::test]
async fn test_secp256k1_key_gen() {
  test_key_gen::<Secp256k1>().await;
}

#[tokio::test]
async fn test_ed25519_key_gen() {
  test_key_gen::<Ed25519>().await;
}
