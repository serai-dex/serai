#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use ciphersuite::Ciphersuite;

/// Generate a view key for usage within Serai.
///
/// `k` is the index of the key to generate (enabling generating multiple view keys within a
/// single context).
pub fn view_key<C: Ciphersuite>(k: u64) -> C::F {
  C::hash_to_F(b"Serai DEX View Key", &k.to_le_bytes())
}
