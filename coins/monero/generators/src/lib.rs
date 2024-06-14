#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use std_shims::{sync::OnceLock, vec::Vec};

use sha3::{Digest, Keccak256};

use curve25519_dalek::edwards::{EdwardsPoint as DalekPoint};

use group::{Group, GroupEncoding};
use dalek_ff_group::EdwardsPoint;

use monero_io::{write_varint, decompress_point};

mod hash_to_point;
pub use hash_to_point::hash_to_point;

#[cfg(test)]
mod tests;

fn keccak256(data: &[u8]) -> [u8; 32] {
  Keccak256::digest(data).into()
}

static H_CELL: OnceLock<DalekPoint> = OnceLock::new();
/// Monero's `H` generator.
///
/// Contrary to convention (`G` for values, `H` for randomness), `H` is used by Monero for amounts
/// within Pedersen commitments.
#[allow(non_snake_case)]
pub fn H() -> DalekPoint {
  *H_CELL.get_or_init(|| {
    decompress_point(keccak256(&EdwardsPoint::generator().to_bytes())).unwrap().mul_by_cofactor()
  })
}

static H_POW_2_CELL: OnceLock<[DalekPoint; 64]> = OnceLock::new();
/// Monero's `H` generator, multiplied by 2**i for i in 1 ..= 64.
///
/// This table is useful when working with amounts, which are u64s.
#[allow(non_snake_case)]
pub fn H_pow_2() -> &'static [DalekPoint; 64] {
  H_POW_2_CELL.get_or_init(|| {
    let mut res = [H(); 64];
    for i in 1 .. 64 {
      res[i] = res[i - 1] + res[i - 1];
    }
    res
  })
}

// The maximum amount of commitments proven for within a single range proof.
const MAX_M: usize = 16;
// The amount of bits the value within a commitment may use.
const N: usize = 64;
// The maximum amount of bits used within a single range proof.
const MAX_MN: usize = MAX_M * N;

/// Container struct for Bulletproofs(+) generators.
#[allow(non_snake_case)]
pub struct Generators {
  pub G: Vec<EdwardsPoint>,
  pub H: Vec<EdwardsPoint>,
}

/// Generate generators as needed for Bulletproofs(+), as Monero does.
///
/// Consumers should not call this function ad-hoc, yet call it within a build script or use a
/// once-initialized static.
pub fn bulletproofs_generators(dst: &'static [u8]) -> Generators {
  let mut preimage = H().compress().to_bytes().to_vec();
  preimage.extend(dst);

  let mut res = Generators { G: Vec::with_capacity(MAX_MN), H: Vec::with_capacity(MAX_MN) };
  for i in 0 .. MAX_MN {
    // We generate a pair of generators per iteration
    let i = 2 * i;

    let mut even = preimage.clone();
    write_varint(&i, &mut even).unwrap();
    res.H.push(EdwardsPoint(hash_to_point(keccak256(&even))));

    let mut odd = preimage.clone();
    write_varint(&(i + 1), &mut odd).unwrap();
    res.G.push(EdwardsPoint(hash_to_point(keccak256(&odd))));
  }
  res
}
