#![allow(non_snake_case)]

use zeroize::{Zeroize, ZeroizeOnDrop};

use rand_core::{RngCore, CryptoRng};

use group::{ff::Field, Group};
use dalek_ff_group::{Scalar, EdwardsPoint};

mod scalar_vector;
pub use scalar_vector::{ScalarVector, weighted_inner_product};
mod point_vector;
pub use point_vector::PointVector;

pub mod weighted_inner_product;
pub mod aggregate_range_proof;

#[cfg(any(test, feature = "tests"))]
pub mod tests;

pub const RANGE_PROOF_BITS: usize = 64;

pub fn padded_pow_of_2(i: usize) -> usize {
  let mut next_pow_of_2 = 1;
  while next_pow_of_2 < i {
    next_pow_of_2 <<= 1;
  }
  next_pow_of_2
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum GeneratorsList {
  GBold1,
  HBold1,
}

// TODO: Table these
#[derive(Clone, Debug)]
pub struct Generators {
  g: EdwardsPoint,
  h: EdwardsPoint,

  g_bold1: &'static [EdwardsPoint],
  h_bold1: &'static [EdwardsPoint],
}

mod generators {
  use std_shims::sync::OnceLock;
  use monero_generators::Generators;
  include!(concat!(env!("OUT_DIR"), "/generators_plus.rs"));
}

impl Generators {
  pub fn new() -> Self {
    let gens = generators::GENERATORS();
    Generators {
      g: EdwardsPoint::generator(),
      h: dalek_ff_group::EdwardsPoint(crate::H()),
      g_bold1: &gens.G,
      h_bold1: &gens.H,
    }
  }

  pub(crate) fn len(&self) -> usize {
    self.g_bold1.len()
  }

  pub fn g(&self) -> EdwardsPoint {
    self.g
  }

  pub fn h(&self) -> EdwardsPoint {
    self.h
  }

  pub(crate) fn generator(&self, list: GeneratorsList, i: usize) -> EdwardsPoint {
    match list {
      GeneratorsList::GBold1 => self.g_bold1[i],
      GeneratorsList::HBold1 => self.h_bold1[i],
    }
  }

  pub(crate) fn reduce(&self, generators: usize) -> Self {
    // Round to the nearest power of 2
    let generators = padded_pow_of_2(generators);
    assert!(generators <= self.g_bold1.len());

    Generators {
      g: self.g,
      h: self.h,
      g_bold1: &self.g_bold1[.. generators],
      h_bold1: &self.h_bold1[.. generators],
    }
  }
}

// Range proof structures

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct RangeCommitment {
  pub value: u64,
  pub mask: Scalar,
}

impl RangeCommitment {
  pub fn zero() -> Self {
    RangeCommitment { value: 0, mask: Scalar::ZERO }
  }

  pub fn new(value: u64, mask: Scalar) -> Self {
    RangeCommitment { value, mask }
  }

  pub fn masking<R: RngCore + CryptoRng>(rng: &mut R, value: u64) -> Self {
    RangeCommitment { value, mask: Scalar::random(rng) }
  }

  /// Calculate a Pedersen commitment, as a point, from the transparent structure.
  pub fn calculate(&self, g: EdwardsPoint, h: EdwardsPoint) -> EdwardsPoint {
    (g * Scalar::from(self.value)) + (h * self.mask)
  }
}

// Returns the little-endian decomposition.
fn u64_decompose(value: u64) -> ScalarVector {
  let mut bits = ScalarVector::new(64);
  for bit in 0 .. 64 {
    bits[bit] = Scalar::from((value >> bit) & 1);
  }
  bits
}
