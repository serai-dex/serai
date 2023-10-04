//! Generators used by Monero in both its Pedersen commitments and Bulletproofs(+).
//!
//! An implementation of Monero's `ge_fromfe_frombytes_vartime`, simply called
//! `hash_to_point` here, is included, as needed to generate generators.

#![cfg_attr(not(feature = "std"), no_std)]

use std_shims::{sync::OnceLock, vec::Vec};

use sha3::{Digest, Keccak256};

use curve25519_dalek::edwards::{EdwardsPoint as DalekPoint, CompressedEdwardsY};

use group::{Group, GroupEncoding};
use dalek_ff_group::EdwardsPoint;

mod varint;
use varint::write_varint;

mod hash_to_point;
pub use hash_to_point::hash_to_point;

fn hash(data: &[u8]) -> [u8; 32] {
  Keccak256::digest(data).into()
}

static H_CELL: OnceLock<DalekPoint> = OnceLock::new();
/// Monero's alternate generator `H`, used for amounts in Pedersen commitments.
#[allow(non_snake_case)]
pub fn H() -> DalekPoint {
  *H_CELL.get_or_init(|| {
    CompressedEdwardsY(hash(&EdwardsPoint::generator().to_bytes()))
      .decompress()
      .unwrap()
      .mul_by_cofactor()
  })
}

static H_POW_2_CELL: OnceLock<[DalekPoint; 64]> = OnceLock::new();
/// Monero's alternate generator `H`, multiplied by 2**i for i in 1 ..= 64.
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

const MAX_M: usize = 16;
const N: usize = 64;
const MAX_MN: usize = MAX_M * N;

/// Container struct for Bulletproofs(+) generators.
#[allow(non_snake_case)]
pub struct Generators {
  pub G: Vec<EdwardsPoint>,
  pub H: Vec<EdwardsPoint>,
}

/// Generate generators as needed for Bulletproofs(+), as Monero does.
pub fn bulletproofs_generators(dst: &'static [u8]) -> Generators {
  let mut res = Generators { G: Vec::with_capacity(MAX_MN), H: Vec::with_capacity(MAX_MN) };
  for i in 0 .. MAX_MN {
    let i = 2 * i;

    let mut even = H().compress().to_bytes().to_vec();
    even.extend(dst);
    let mut odd = even.clone();

    write_varint(&i.try_into().unwrap(), &mut even).unwrap();
    write_varint(&(i + 1).try_into().unwrap(), &mut odd).unwrap();
    res.H.push(EdwardsPoint(hash_to_point(hash(&even))));
    res.G.push(EdwardsPoint(hash_to_point(hash(&odd))));
  }
  res
}
