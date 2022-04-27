use lazy_static::lazy_static;
use thiserror::Error;

use rand_core::{RngCore, CryptoRng};

use tiny_keccak::{Hasher, Keccak};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  scalar::Scalar,
  edwards::{EdwardsPoint, EdwardsBasepointTable, CompressedEdwardsY}
};

use monero::util::key;

#[cfg(feature = "multisig")]
pub mod frost;

pub mod key_image;
pub mod clsag;

#[link(name = "wrapper")]
extern "C" {
  fn c_hash_to_point(point: *const u8);
  pub(crate) fn c_verify_clsag(
    serialized_len: usize, serialized: *const u8, I: *const u8,
    ring_size: u8, ring: *const u8, msg: *const u8, pseudo_out: *const u8
  ) -> bool;
}

#[derive(Error, Debug)]
pub enum SignError {
  #[error("internal error ({0})")]
  InternalError(String),
  #[error("invalid discrete log equality proof")]
  InvalidDLEqProof,
  #[error("invalid key image {0}")]
  InvalidKeyImage(usize),
  #[error("invalid ring member (member {0}, ring size {1})")]
  InvalidRingMember(u8, u8),
  #[error("invalid secret for ring (index {0})")]
  InvalidSecret(u8),
  #[error("invalid commitment {0}")]
  InvalidCommitment(usize),
  #[error("invalid share {0}")]
  InvalidShare(usize),
  #[error("invalid signature")]
  InvalidSignature
}

// Allows using a modern rand as dalek's is notoriously dated
pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
  let mut r = [0; 64];
  rng.fill_bytes(&mut r);
  Scalar::from_bytes_mod_order_wide(&r)
}

lazy_static! {
  static ref H_TABLE: EdwardsBasepointTable = EdwardsBasepointTable::create(&key::H.point.decompress().unwrap());
}

// aG + bH
pub fn commitment(randomness: &Scalar, amount: u64) -> EdwardsPoint {
  (randomness * &ED25519_BASEPOINT_TABLE) + (&Scalar::from(amount) * &*H_TABLE)
}

pub fn hash_to_scalar(data: &[u8]) -> Scalar {
  let mut keccak = Keccak::v256();
  keccak.update(data);

  let mut res = [0; 32];
  keccak.finalize(&mut res);
  Scalar::from_bytes_mod_order(res)
}

pub fn hash_to_point(point: &EdwardsPoint) -> EdwardsPoint {
  let mut bytes = point.compress().to_bytes();
  unsafe {
    c_hash_to_point(bytes.as_mut_ptr());
  }
  CompressedEdwardsY::from_slice(&bytes).decompress().unwrap()
}
