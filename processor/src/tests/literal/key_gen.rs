use crate::tests::test_key_gen;

#[cfg(feature = "secp256k1")]
#[tokio::test]
async fn test_secp256k1_key_gen() {
  test_key_gen::<frost::curve::Secp256k1>().await;
}

#[cfg(feature = "ed25519")]
#[tokio::test]
async fn test_ed25519_key_gen() {
  test_key_gen::<frost::curve::Ed25519>().await;
}
