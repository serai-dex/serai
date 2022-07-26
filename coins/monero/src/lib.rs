use lazy_static::lazy_static;
use rand_core::{RngCore, CryptoRng};

use tiny_keccak::{Hasher, Keccak};

use curve25519_dalek::{
  constants::{ED25519_BASEPOINT_POINT, ED25519_BASEPOINT_TABLE},
  scalar::Scalar,
  edwards::{EdwardsPoint, EdwardsBasepointTable, CompressedEdwardsY},
};

#[cfg(feature = "multisig")]
pub mod frost;

mod serialize;

pub mod ringct;

pub mod transaction;
pub mod block;

pub mod rpc;
pub mod wallet;

#[cfg(test)]
mod tests;

lazy_static! {
  static ref H: EdwardsPoint =
    CompressedEdwardsY(hash(&ED25519_BASEPOINT_POINT.compress().to_bytes()))
      .decompress()
      .unwrap()
      .mul_by_cofactor();
  static ref H_TABLE: EdwardsBasepointTable = EdwardsBasepointTable::create(&H);
}

#[allow(non_snake_case)]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Commitment {
  pub mask: Scalar,
  pub amount: u64,
}

impl Commitment {
  pub fn zero() -> Commitment {
    Commitment { mask: Scalar::one(), amount: 0 }
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
  let scalar = Scalar::from_bytes_mod_order(hash(data));
  // Monero will explicitly error in this case
  // This library acknowledges its practical impossibility of it occurring, and doesn't bother to
  // code in logic to handle it. That said, if it ever occurs, something must happen in order to
  // not generate/verify a proof we believe to be valid when it isn't
  assert!(scalar != Scalar::zero(), "ZERO HASH: {:?}", data);
  scalar
}
