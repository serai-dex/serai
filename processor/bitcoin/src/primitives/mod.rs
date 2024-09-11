use ciphersuite::{Ciphersuite, Secp256k1};

use bitcoin_serai::bitcoin::key::{Parity, XOnlyPublicKey};

pub(crate) mod output;
pub(crate) mod transaction;
pub(crate) mod block;

pub(crate) fn x_coord_to_even_point(key: &[u8]) -> Option<<Secp256k1 as Ciphersuite>::G> {
  if key.len() != 32 {
    None?
  };

  // Read the x-only public key
  let key = XOnlyPublicKey::from_slice(key).ok()?;
  // Convert to a full public key
  let key = key.public_key(Parity::Even);
  // Convert to k256 (from libsecp256k1)
  Secp256k1::read_G(&mut key.serialize().as_slice()).ok()
}
