//! Generators used by Monero in both its Pedersen commitments and Bulletproofs(+).
//! An implementation of Monero's `ge_fromfe_frombytes_vartime`, simply called
//! `hash_to_point` here, is included, as needed to generate generators.

use lazy_static::lazy_static;

use sha3::{Digest, Keccak256};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_POINT,
  edwards::{EdwardsPoint as DalekPoint, CompressedEdwardsY},
};

use group::Group;
use dalek_ff_group::EdwardsPoint;

mod varint;
use varint::write_varint;

mod hash_to_point;
pub use hash_to_point::hash_to_point;

fn hash(data: &[u8]) -> [u8; 32] {
  Keccak256::digest(data).into()
}

lazy_static! {
  /// Monero alternate generator `H`, used for amounts in Pedersen commitments.
  pub static ref H: DalekPoint =
    CompressedEdwardsY(hash(&ED25519_BASEPOINT_POINT.compress().to_bytes()))
      .decompress()
      .unwrap()
      .mul_by_cofactor();
}

const MAX_M: usize = 16;
const N: usize = 64;
const MAX_MN: usize = MAX_M * N;

/// Container struct for Bulletproofs(+) generators.
#[allow(non_snake_case)]
pub struct Generators {
  pub G: [EdwardsPoint; MAX_MN],
  pub H: [EdwardsPoint; MAX_MN],
}

/// Generate generators as needed for Bulletproofs(+), as Monero does.
pub fn bulletproofs_generators(dst: &'static [u8]) -> Generators {
  let mut res =
    Generators { G: [EdwardsPoint::identity(); MAX_MN], H: [EdwardsPoint::identity(); MAX_MN] };
  for i in 0 .. MAX_MN {
    let i = 2 * i;

    let mut even = H.compress().to_bytes().to_vec();
    even.extend(dst);
    let mut odd = even.clone();

    write_varint(&i.try_into().unwrap(), &mut even).unwrap();
    write_varint(&(i + 1).try_into().unwrap(), &mut odd).unwrap();
    res.H[i / 2] = EdwardsPoint(hash_to_point(hash(&even)));
    res.G[i / 2] = EdwardsPoint(hash_to_point(hash(&odd)));
  }
  res
}
