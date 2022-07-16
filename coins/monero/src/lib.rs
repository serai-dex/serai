use std::slice;

use lazy_static::lazy_static;
use rand_core::{RngCore, CryptoRng};

use subtle::ConstantTimeEq;

use tiny_keccak::{Hasher, Keccak};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
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
  static ref H: EdwardsPoint = CompressedEdwardsY(
    hex::decode("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")
      .unwrap()
      .try_into()
      .unwrap()
  )
  .decompress()
  .unwrap();
  static ref H_TABLE: EdwardsBasepointTable = EdwardsBasepointTable::create(&*H);
}

// Function from libsodium our subsection of Monero relies on. Implementing it here means we don't
// need to link against libsodium
#[no_mangle]
unsafe extern "C" fn crypto_verify_32(a: *const u8, b: *const u8) -> isize {
  isize::from(slice::from_raw_parts(a, 32).ct_eq(slice::from_raw_parts(b, 32)).unwrap_u8()) - 1
}

// Offer a wide reduction to C. Our seeded RNG prevented Monero from defining an unbiased scalar
// generation function, and in order to not use Monero code (which would require propagating its
// license), the function was rewritten. It was rewritten with wide reduction, instead of rejection
// sampling however, hence the need for this function
#[no_mangle]
unsafe extern "C" fn monero_wide_reduce(value: *mut u8) {
  let res =
    Scalar::from_bytes_mod_order_wide(std::slice::from_raw_parts(value, 64).try_into().unwrap());
  for (i, b) in res.to_bytes().iter().enumerate() {
    value.add(i).write(*b);
  }
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
  Scalar::from_bytes_mod_order(hash(&data))
}
