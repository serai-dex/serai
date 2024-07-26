#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use std_shims::{sync::LazyLock, vec::Vec};

use sha3::{Digest, Keccak256};

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, edwards::EdwardsPoint};

use monero_io::{write_varint, decompress_point};

mod hash_to_point;
pub use hash_to_point::hash_to_point;

#[cfg(test)]
mod tests;

fn keccak256(data: &[u8]) -> [u8; 32] {
  Keccak256::digest(data).into()
}

/// Monero's `H` generator.
///
/// Contrary to convention (`G` for values, `H` for randomness), `H` is used by Monero for amounts
/// within Pedersen commitments.
#[allow(non_snake_case)]
pub static H: LazyLock<EdwardsPoint> = LazyLock::new(|| {
  decompress_point(keccak256(&ED25519_BASEPOINT_POINT.compress().to_bytes()))
    .unwrap()
    .mul_by_cofactor()
});

static H_POW_2_CELL: LazyLock<[EdwardsPoint; 64]> = LazyLock::new(|| {
  let mut res = [*H; 64];
  for i in 1 .. 64 {
    res[i] = res[i - 1] + res[i - 1];
  }
  res
});
/// Monero's `H` generator, multiplied by 2**i for i in 1 ..= 64.
///
/// This table is useful when working with amounts, which are u64s.
#[allow(non_snake_case)]
pub fn H_pow_2() -> &'static [EdwardsPoint; 64] {
  &H_POW_2_CELL
}

/// The maximum amount of commitments provable for within a single range proof.
pub const MAX_COMMITMENTS: usize = 16;
/// The amount of bits a value within a commitment may use.
pub const COMMITMENT_BITS: usize = 64;
/// The logarithm (over 2) of the amount of bits a value within a commitment may use.
pub const LOG_COMMITMENT_BITS: usize = 6; // 2 ** 6 == N

/// Container struct for Bulletproofs(+) generators.
#[allow(non_snake_case)]
pub struct Generators {
  /// The G (bold) vector of generators.
  pub G: Vec<EdwardsPoint>,
  /// The H (bold) vector of generators.
  pub H: Vec<EdwardsPoint>,
}

/// Generate generators as needed for Bulletproofs(+), as Monero does.
///
/// Consumers should not call this function ad-hoc, yet call it within a build script or use a
/// once-initialized static.
pub fn bulletproofs_generators(dst: &'static [u8]) -> Generators {
  // The maximum amount of bits used within a single range proof.
  const MAX_MN: usize = MAX_COMMITMENTS * COMMITMENT_BITS;

  let mut preimage = H.compress().to_bytes().to_vec();
  preimage.extend(dst);

  let mut res = Generators { G: Vec::with_capacity(MAX_MN), H: Vec::with_capacity(MAX_MN) };
  for i in 0 .. MAX_MN {
    // We generate a pair of generators per iteration
    let i = 2 * i;

    let mut even = preimage.clone();
    write_varint(&i, &mut even).unwrap();
    res.H.push(hash_to_point(keccak256(&even)));

    let mut odd = preimage.clone();
    write_varint(&(i + 1), &mut odd).unwrap();
    res.G.push(hash_to_point(keccak256(&odd)));
  }
  res
}
