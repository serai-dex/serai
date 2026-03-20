//! Test helpers for generating random instances of primitive types.

use rand_core::{RngCore, CryptoRng};

use crate::{BlockHash, address::{SeraiAddress, ExternalAddress}, crypto::{Public, ExternalKey}};

/// Generate a random [`ExternalAddress`].
pub fn random_external_address<R: RngCore + CryptoRng>(rng: &mut R) -> ExternalAddress {
  let mut key = [0; 32];
  rng.fill_bytes(&mut key);
  ExternalAddress::try_from(key.to_vec()).unwrap()
}

/// Generate a random [`SeraiAddress`].
pub fn random_serai_address<R: RngCore + CryptoRng>(rng: &mut R) -> SeraiAddress {
  let mut key = [0; 32];
  rng.fill_bytes(&mut key);
  SeraiAddress(key)
}

/// Generate a random [`Public`].
pub fn random_public<R: RngCore + CryptoRng>(rng: &mut R) -> Public {
  let mut key = [0; 32];
  rng.fill_bytes(&mut key);
  Public(key)
}

/// Generate a random schnorrkel keypair and its [`Public`] wrapper.
pub fn random_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> (schnorrkel::Keypair, Public) {
  let keypair = schnorrkel::Keypair::generate_with(rng);
  let public = Public(keypair.public.to_bytes());
  (keypair, public)
}

/// Generate a random [`ExternalKey`].
pub fn random_external_key<R: RngCore + CryptoRng>(rng: &mut R) -> ExternalKey {
  let mut key = [0; 32];
  rng.fill_bytes(&mut key);
  ExternalKey(key.to_vec().try_into().unwrap())
}

/// Generate a random [`BlockHash`].
pub fn random_block_hash<R: RngCore + CryptoRng>(rng: &mut R) -> BlockHash {
  let mut hash = [0; 32];
  rng.fill_bytes(&mut hash);
  BlockHash(hash)
}
