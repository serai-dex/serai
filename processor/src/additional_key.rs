use ciphersuite::Ciphersuite;

use crate::networks::Network;

// Generate a static additional key for a given chain in a globally consistent manner
// Doesn't consider the current group key to increase the simplicity of verifying Serai's status
// Takes an index, k, to support protocols which use multiple secondary keys
// Presumably a view key
pub fn additional_key<N: Network>(k: u64) -> <N::Curve as Ciphersuite>::F {
  <N::Curve as Ciphersuite>::hash_to_F(
    b"Serai DEX Additional Key",
    &[N::ID.as_bytes(), &k.to_le_bytes()].concat(),
  )
}
