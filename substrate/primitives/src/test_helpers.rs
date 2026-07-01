//! Test helpers for generating random instances of primitive types.

use alloc::{vec, vec::Vec};
use embedwards25519::Embedwards25519;
use core::ops::{Bound, RangeBounds};

use rand_core::{RngCore, CryptoRng};

use ciphersuite::{group::ff::Field as _, group::GroupEncoding as _, WrappedGroup};
use dalek_ff_group::{Ristretto, RistrettoPoint};
use secq256k1::Secq256k1;

use crate::{
  BlockHash,
  address::{ExternalAddress, SeraiAddress},
  crypto::{EmbeddedEllipticCurveKeys, ExternalKey, KeyPair, Public},
  network_id::ExternalNetworkId,
  prelude::{NetworkId, Slash, SlashReport},
  validator_sets::{ExternalValidatorSet, Session},
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

/// Generate a random byte vector of a specific length.
pub fn random_vec_of_len<R: RngCore + CryptoRng>(rng: &mut R, len: usize) -> Vec<u8> {
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

/// Generate a random [`Vec<SeraiAddress>`].
pub fn random_serai_addresses<R: RngCore + CryptoRng>(
  rng: &mut R,
  num: usize,
) -> Vec<SeraiAddress> {
  (0 .. num).map(|_| random_serai_address(rng)).collect()
}

/// Generate a random [`Public`].
pub fn random_public<R: RngCore + CryptoRng>(rng: &mut R) -> Public {
  Public(random_bytes(rng))
}

/// Generate a random schnorrkel keypair and its [`Public`] wrapper.
pub fn random_schnorrkel_keypair<R: RngCore + CryptoRng>(
  rng: &mut R,
) -> (schnorrkel::Keypair, Public) {
  let keypair = schnorrkel::Keypair::generate_with(rng);
  let public = Public(keypair.public.to_bytes());
  (keypair, public)
}

/// Generate a valid validator identity and random auxiliary keys for a given network.
pub fn random_validator_and_auxiliary_keys<R: RngCore + CryptoRng>(
  rng: &mut R,
  network: ExternalNetworkId,
) -> (SeraiAddress, EmbeddedEllipticCurveKeys, EmbeddedEllipticCurveKeys) {
  let (_, public) = random_schnorrkel_keypair(rng);
  let bytes = public.0;

  let network_aux = match network {
    ExternalNetworkId::Bitcoin => {
      EmbeddedEllipticCurveKeys::Bitcoin(bytes, random_bytes::<R, 33>(rng).into())
    }
    ExternalNetworkId::Ethereum => {
      EmbeddedEllipticCurveKeys::Ethereum(bytes, random_bytes::<R, 33>(rng).into())
    }
    ExternalNetworkId::Monero => EmbeddedEllipticCurveKeys::Monero(bytes),
  };

  (random_serai_address(rng), random_serai_embedded_elliptic_curve_keys(rng), network_aux)
}

/// Generate a random [`ExternalKey`].
pub fn random_external_network_key<R: RngCore + CryptoRng>(rng: &mut R) -> ExternalKey {
  let len = usize::try_from(rng.next_u32() % ExternalKey::MAX_SIZE).unwrap();
  let mut external_key = vec![0; len];
  rng.fill_bytes(&mut external_key);
  ExternalKey(external_key.try_into().unwrap())
}

/// Generate a random [`KeyPair`], combining a random [`Public`] and [`ExternalKey`].
pub fn random_vset_key_pair<R: RngCore + CryptoRng>(rng: &mut R) -> KeyPair {
  let (_, schnorrkel_public) = random_schnorrkel_keypair(rng);
  let external_network_key = random_external_network_key(rng);
  KeyPair(schnorrkel_public, external_network_key)
}

#[test]
fn random_external_key_is_in_range() {
  for _ in 0 .. (128 * ExternalKey::MAX_SIZE) {
    random_external_network_key(&mut rand_core::OsRng);
  }
}

/// Generate a random [`BlockHash`].
pub fn random_block_hash<R: RngCore + CryptoRng>(rng: &mut R) -> BlockHash {
  BlockHash(random_bytes(rng))
}

/// Generate a random [`ExternalNetworkId`].
pub fn random_network_id<R: RngCore + CryptoRng>(rng: &mut R) -> NetworkId {
  let all: Vec<_> = NetworkId::all().collect();
  all[usize::try_from(rng.next_u64() % u64::try_from(all.len()).unwrap()).unwrap()]
}

/// Generate a random [`ExternalNetworkId`].
pub fn random_external_network_id<R: RngCore + CryptoRng>(rng: &mut R) -> ExternalNetworkId {
  let all: Vec<_> = ExternalNetworkId::all().collect();
  all[usize::try_from(rng.next_u64() % u64::try_from(all.len()).unwrap()).unwrap()]
}

/// Generate a random [`ExternalValidatorSet`].
pub fn random_external_validator_set<R: RngCore + CryptoRng>(rng: &mut R) -> ExternalValidatorSet {
  ExternalValidatorSet {
    network: random_external_network_id(rng),
    session: Session(rng.next_u32()),
  }
}

pub fn random_slash_report<R: RngCore + CryptoRng>(rng: &mut R) -> SlashReport {
  let num_slashes = usize::try_from(rng.next_u32() % 4).unwrap();
  let mut slashes = Vec::with_capacity(num_slashes);
  for _ in 0 .. num_slashes {
    // Randomly choose between Points and Fatal slash
    if rng.next_u32() % 2 == 0 {
      slashes.push(Slash::Points(rng.next_u32()));
    } else {
      slashes.push(Slash::Fatal);
    }
  }

  SlashReport::try_from(slashes).unwrap()
}

/// Generate a random genesis
pub fn random_genesis<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
  random_bytes::<R, 32>(rng)
}

/// Generate a random block number.
pub fn random_block_number<R: RngCore + CryptoRng>(rng: &mut R) -> u64 {
  rng.next_u64()
}

/// A default [`ExternalValidatorSet`] for tests where the set value doesn't matter.
pub fn default_test_validator_set() -> ExternalValidatorSet {
  ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) }
}

/// Generate a random [`RistrettoPoint`].
pub fn random_ristretto_public_key<R: RngCore + CryptoRng>(rng: &mut R) -> RistrettoPoint {
  <Ristretto as WrappedGroup>::generator() * <Ristretto as WrappedGroup>::F::random(&mut *rng)
}

/// Generate a random byte array for a Ristretto public key.
pub fn random_ristretto_public_key_bytes<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
  random_ristretto_public_key(rng).to_bytes()
}

/// Generate a random [`Embedwards25519`] public key.
pub fn random_embedwards_key<R: RngCore + CryptoRng>(
  rng: &mut R,
) -> <Embedwards25519 as WrappedGroup>::G {
  <Embedwards25519 as WrappedGroup>::generator() *
    <Embedwards25519 as WrappedGroup>::F::random(&mut *rng)
}

/// Generate a random byte array for a Embedwards25519 public key.
pub fn random_embedwards_key_bytes<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
  random_embedwards_key(rng).to_bytes()
}

/// Generate a random [`EmbeddedEllipticCurveKeys`] for `NetworkId::Serai`.
pub fn random_serai_embedded_elliptic_curve_keys<R: RngCore + CryptoRng>(
  rng: &mut R,
) -> EmbeddedEllipticCurveKeys {
  EmbeddedEllipticCurveKeys::Serai(random_ristretto_public_key(rng).to_bytes())
}

/// Generate a random [`EmbeddedEllipticCurveKeys`] for the given network.
pub fn random_embedded_elliptic_curve_keys<R: RngCore + CryptoRng>(
  rng: &mut R,
  network: NetworkId,
) -> EmbeddedEllipticCurveKeys {
  let substrate_key = random_ristretto_public_key(rng).to_bytes();

  match network {
    NetworkId::Serai => EmbeddedEllipticCurveKeys::Serai(substrate_key),
    NetworkId::External(ExternalNetworkId::Bitcoin) => {
      let secq_point =
        (Secq256k1::generator() * <Secq256k1 as WrappedGroup>::F::random(&mut *rng)).to_bytes();
      EmbeddedEllipticCurveKeys::Bitcoin(substrate_key, secq_point)
    }
    NetworkId::External(ExternalNetworkId::Ethereum) => {
      let secq_point =
        (Secq256k1::generator() * <Secq256k1 as WrappedGroup>::F::random(&mut *rng)).to_bytes();
      EmbeddedEllipticCurveKeys::Ethereum(substrate_key, secq_point)
    }
    NetworkId::External(ExternalNetworkId::Monero) => {
      EmbeddedEllipticCurveKeys::Monero(substrate_key)
    }
  }
}

pub fn all_networks() -> Vec<NetworkId> {
  NetworkId::all().collect()
}

pub fn all_external_networks() -> Vec<ExternalNetworkId> {
  ExternalNetworkId::all().collect()
}
