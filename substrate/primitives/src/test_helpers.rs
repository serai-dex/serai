//! Test helpers for generating random instances of primitive types.

use alloc::{vec, vec::Vec};

use rand_core::{RngCore, CryptoRng};

use crate::{
  BlockHash,
  address::{SeraiAddress, ExternalAddress},
  crypto::{Public, ExternalKey},
  network_id::ExternalNetworkId,
  validator_sets::{ExternalValidatorSet, Session},
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

/// Generate a random `Vec<u8>` with a random length between 1 and 128.
pub fn random_vec_u8<R: RngCore + CryptoRng>(rng: &mut R) -> Vec<u8> {
  let len = usize::try_from(rng.next_u32() % 128).unwrap() + 1;
  random_vec_of_len(rng, len)
}

/// Generate a random byte vector of a specific length.
pub fn random_vec_of_len<R: RngCore + CryptoRng>(rng: &mut R, len: usize) -> Vec<u8> {
  let mut bytes = vec![0u8; len];
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

/// Generate a random global session ID (`[u8; 32]`).
pub fn random_global_session<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
  random_bytes_32(rng)
}

/// Generate a random genesis
pub fn random_genesis<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
  random_bytes_32(rng)
}

/// Generate a random block number.
pub fn random_block_number<R: RngCore + CryptoRng>(rng: &mut R) -> u64 {
  rng.next_u64()
}

/// Generate a random [`ExternalNetworkId`].
pub fn random_external_network_id<R: RngCore + CryptoRng>(rng: &mut R) -> ExternalNetworkId {
  let all: Vec<_> = ExternalNetworkId::all().collect();
  all[usize::try_from(rng.next_u32()).unwrap() % all.len()]
}

/// Generate a random [`ExternalValidatorSet`].
pub fn random_validator_set<R: RngCore + CryptoRng>(rng: &mut R) -> ExternalValidatorSet {
  ExternalValidatorSet {
    network: random_external_network_id(rng),
    session: Session(rng.next_u32()),
  }
}

/// A default [`ExternalValidatorSet`] for tests where the set value doesn't matter.
pub fn default_test_validator_set() -> ExternalValidatorSet {
  ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) }
}
