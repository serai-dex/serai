//! Test helpers for generating random instances of primitive types.

use rand_core::{RngCore, CryptoRng};

use crate::{
  BlockHash,
  address::{SeraiAddress, ExternalAddress},
  crypto::{Public, ExternalKey},
};

/// Generate a random 32-byte array.
pub fn random_bytes_32<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
  let mut bytes = [0u8; 32];
  rng.fill_bytes(&mut bytes);
  bytes
}

/// Generate a random 64-byte array.
pub fn random_bytes_64<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 64] {
  let mut bytes = [0u8; 64];
  rng.fill_bytes(&mut bytes);
  bytes
}

/// Generate a random [`ExternalAddress`].
pub fn random_external_address<R: RngCore + CryptoRng>(rng: &mut R) -> ExternalAddress {
  ExternalAddress::try_from(random_bytes_32(rng).to_vec()).unwrap()
}

/// Generate a random [`SeraiAddress`].
pub fn random_serai_address<R: RngCore + CryptoRng>(rng: &mut R) -> SeraiAddress {
  SeraiAddress(random_bytes_32(rng))
}

/// Generate a random [`Public`].
pub fn random_public<R: RngCore + CryptoRng>(rng: &mut R) -> Public {
  Public(random_bytes_32(rng))
}

/// Generate a random schnorrkel keypair and its [`Public`] wrapper.
pub fn random_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (schnorrkel::Keypair, Public) {
  let keypair = schnorrkel::Keypair::generate_with(rng);
  let public = Public(keypair.public.to_bytes());
  (keypair, public)
}

/// Generate a random [`ExternalKey`].
pub fn random_external_key<R: RngCore + CryptoRng>(rng: &mut R) -> ExternalKey {
  ExternalKey(random_bytes_32(rng).to_vec().try_into().unwrap())
}

/// Generate a random [`BlockHash`].
pub fn random_block_hash<R: RngCore + CryptoRng>(rng: &mut R) -> BlockHash {
  BlockHash(random_bytes_32(rng))
}

/// Generate a random global session ID (`[u8; 32]`).
pub fn random_global_session<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
  random_bytes_32(rng)
}
