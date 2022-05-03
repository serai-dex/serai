use lazy_static::lazy_static;

use rand_core::{RngCore, CryptoRng};

use tiny_keccak::{Hasher, Keccak};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  scalar::Scalar,
  edwards::{EdwardsPoint, EdwardsBasepointTable, CompressedEdwardsY}
};

use monero::util::key::H;

use transcript::DigestTranscript;

#[cfg(feature = "multisig")]
pub mod frost;

pub mod key_image;
pub mod bulletproofs;
pub mod clsag;

pub mod rpc;
pub mod transaction;

#[link(name = "wrapper")]
extern "C" {
  pub(crate) fn free(ptr: *const u8);
  fn c_hash_to_point(point: *const u8);
  pub(crate) fn c_generate_bp(len: u8, amounts: *const u64, masks: *const [u8; 32]) -> *const u8;
  pub(crate) fn c_verify_bp(
    serialized_len: usize, serialized: *const u8,
    commitments_len: u8, commitments: *const [u8; 32]
  ) -> bool;
  pub(crate) fn c_verify_clsag(
    serialized_len: usize, serialized: *const u8, I: *const u8,
    ring_size: u8, ring: *const u8, msg: *const u8, pseudo_out: *const u8
  ) -> bool;
}

// Allows using a modern rand as dalek's is notoriously dated
pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
  let mut r = [0; 64];
  rng.fill_bytes(&mut r);
  Scalar::from_bytes_mod_order_wide(&r)
}

lazy_static! {
  static ref H_TABLE: EdwardsBasepointTable = EdwardsBasepointTable::create(&H.point.decompress().unwrap());
}

pub(crate) type Transcript = DigestTranscript::<blake2::Blake2b512>;

#[allow(non_snake_case)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Commitment {
  pub mask: Scalar,
  pub amount: u64
}

impl Commitment {
  pub fn zero() -> Commitment {
    Commitment { mask: Scalar::one(), amount: 0}
  }

  pub fn new(mask: Scalar, amount: u64) -> Commitment {
    Commitment { mask, amount }
  }

  pub fn calculate(&self) -> EdwardsPoint {
    (&self.mask * &ED25519_BASEPOINT_TABLE) + (&Scalar::from(self.amount) * &*H_TABLE)
  }
}

pub fn hash(data: &[u8]) -> [u8; 32] {
  let mut keccak = Keccak::v256();
  keccak.update(data);
  let mut res = [0; 32];
  keccak.finalize(&mut res);
  res
}

pub fn hash_to_scalar(data: &[u8]) -> Scalar {
  Scalar::from_bytes_mod_order(hash(&data))
}

pub fn hash_to_point(point: &EdwardsPoint) -> EdwardsPoint {
  let mut bytes = point.compress().to_bytes();
  unsafe {
    c_hash_to_point(bytes.as_mut_ptr());
  }
  CompressedEdwardsY::from_slice(&bytes).decompress().unwrap()
}
