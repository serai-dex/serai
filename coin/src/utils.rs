use frost::curve::Curve;

use crate::Coin;

// Generate a static additional key for a given chain in a globally consistent manner
// Doesn't consider the current group key to increase the simplicity of verifying Serai's status
// Takes an index, k, to support protocols which use multiple secondary keys
// Presumably a view key
pub(crate) fn additional_key<C: Coin>(k: u64) -> <C::Curve as Curve>::F {
  C::Curve::hash_to_F(b"Serai DEX Additional Key", &[C::ID, &k.to_le_bytes()].concat())
}
