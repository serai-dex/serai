use lazy_static::lazy_static;
use rand_core::{RngCore, CryptoRng};

use tiny_keccak::{Hasher, Keccak};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  scalar::Scalar,
  edwards::{EdwardsPoint, EdwardsBasepointTable, CompressedEdwardsY}
};

#[cfg(feature = "multisig")]
pub mod frost;

mod serialize;

pub mod bulletproofs;
pub mod clsag;

pub mod rpc;
pub mod transaction;
pub mod wallet;


#[cfg(test)]
mod tests;

lazy_static! {
  static ref H: EdwardsPoint = CompressedEdwardsY(
    hex::decode("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94").unwrap().try_into().unwrap()
  ).decompress().unwrap();
  static ref H_TABLE: EdwardsBasepointTable = EdwardsBasepointTable::create(&*H);
}

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

// Allows using a modern rand as dalek's is notoriously dated
pub fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Scalar {
  let mut r = [0; 64];
  rng.fill_bytes(&mut r);
  Scalar::from_bytes_mod_order_wide(&r)
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
    #[link(name = "wrapper")]
    extern "C" {
      fn c_hash_to_point(point: *const u8);
    }

    c_hash_to_point(bytes.as_mut_ptr());
  }
  CompressedEdwardsY::from_slice(&bytes).decompress().unwrap()
}

pub fn generate_key_image(secret: &Scalar) -> EdwardsPoint {
  secret * hash_to_point(&(secret * &ED25519_BASEPOINT_TABLE))
}
