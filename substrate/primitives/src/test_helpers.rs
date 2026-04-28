//! Test helpers for generating random instances of primitive types.

use core::ops::{Bound, RangeBounds};
use alloc::{vec, vec::Vec};

use rand_core::{RngCore, CryptoRng};

use crate::{
  BlockHash,
  address::{SeraiAddress, ExternalAddress},
  crypto::{Public, ExternalKey},
  network_id::ExternalNetworkId,
  validator_sets::{Session, ExternalValidatorSet},
};

/// Generate a random byte array.
pub fn random_bytes<R: RngCore + CryptoRng, const N: usize>(rng: &mut R) -> [u8; N] {
  let mut bytes = [0u8; N];
  rng.fill_bytes(&mut bytes);
  bytes
}

/// Generate a random byte vector of a length within a range.
pub fn random_vec_u8<R: RngCore + CryptoRng>(rng: &mut R, len: impl RangeBounds<usize>) -> Vec<u8> {
  let len = {
    let inclusive_start = match len.start_bound() {
      Bound::Included(start) => *start,
      Bound::Excluded(start) => start + 1,
      Bound::Unbounded => 0,
    };
    let inclusive_end = match len.end_bound() {
      Bound::Included(end) => *end,
      Bound::Excluded(end) => end - 1,
      Bound::Unbounded => panic!("do not request a random vector of unbounded length"),
    };
    let range_len = inclusive_end
      .checked_sub(inclusive_start)
      .expect("requested a random vector for a length within a range with no elements") +
      1;
    let i = usize::try_from(rng.next_u64() % u64::try_from(range_len).unwrap()).unwrap();
    inclusive_start + i
  };

  let mut bytes = vec![0u8; len];
  rng.fill_bytes(&mut bytes);
  bytes
}

#[test]
fn random_vec_u8_handles_ranges_correctly() {
  use rand_core::OsRng;
  for _ in 0 .. 128 {
    assert_eq!(random_vec_u8(&mut OsRng, 0 ..= 0).len(), 0);
    assert_eq!(random_vec_u8(&mut OsRng, 0 .. 1).len(), 0);
    assert_eq!(random_vec_u8(&mut OsRng, ..= 0).len(), 0);
    assert_eq!(random_vec_u8(&mut OsRng, .. 1).len(), 0);
  }
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
  SeraiAddress(random_bytes(rng))
}

/// Generate a random [`Public`].
pub fn random_public<R: RngCore + CryptoRng>(rng: &mut R) -> Public {
  Public(random_bytes(rng))
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
  BlockHash(random_bytes(rng))
}

/// Generate a random [`ExternalNetworkId`].
pub fn random_external_network_id<R: RngCore + CryptoRng>(rng: &mut R) -> ExternalNetworkId {
  let all: Vec<_> = ExternalNetworkId::all().collect();
  all[usize::try_from(rng.next_u64() % u64::try_from(all.len()).unwrap()).unwrap()]
}

/// Generate a random [`ExternalValidatorSet`].
pub fn random_validator_set<R: RngCore + CryptoRng>(rng: &mut R) -> ExternalValidatorSet {
  ExternalValidatorSet {
    network: random_external_network_id(rng),
    session: Session(rng.next_u32()),
  }
}
