//! Test helpers for generating random instances of primitive types.

use alloc::vec;

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
  let len = usize::try_from(rng.next_u32() % ExternalAddress::MAX_SIZE).unwrap();
  let mut external_address = vec![0; len];
  rng.fill_bytes(&mut external_address);
  ExternalAddress::try_from(external_address).unwrap()
}

#[test]
fn random_external_address_is_in_range() {
  for _ in 0 .. (128 * ExternalAddress::MAX_SIZE) {
    random_external_address(&mut rand_core::OsRng);
  }
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
  let len = usize::try_from(rng.next_u32() % ExternalKey::MAX_SIZE).unwrap();
  let mut external_key = vec![0; len];
  rng.fill_bytes(&mut external_key);
  ExternalKey(external_key.try_into().unwrap())
}

#[test]
fn random_external_key_is_in_range() {
  for _ in 0 .. (128 * ExternalKey::MAX_SIZE) {
    random_external_key(&mut rand_core::OsRng);
  }
}

/// Generate a random [`BlockHash`].
pub fn random_block_hash<R: RngCore + CryptoRng>(rng: &mut R) -> BlockHash {
  BlockHash(random_bytes_32(rng))
}
