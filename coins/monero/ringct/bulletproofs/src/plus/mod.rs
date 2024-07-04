#![allow(non_snake_case)]

use std_shims::{sync::OnceLock, vec};

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar, edwards::EdwardsPoint};

use monero_generators::{H, Generators};

pub(crate) use crate::scalar_vector::ScalarVector;

mod point_vector;
pub(crate) use point_vector::PointVector;

pub(crate) mod transcript;
pub(crate) mod weighted_inner_product;
pub(crate) use weighted_inner_product::*;
pub(crate) mod aggregate_range_proof;
pub(crate) use aggregate_range_proof::*;

pub(crate) fn padded_pow_of_2(i: usize) -> usize {
  let mut next_pow_of_2 = 1;
  while next_pow_of_2 < i {
    next_pow_of_2 <<= 1;
  }
  next_pow_of_2
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum GeneratorsList {
  GBold,
  HBold,
}

// TODO: Table these
#[derive(Clone, Debug)]
pub(crate) struct BpPlusGenerators {
  g_bold: &'static [EdwardsPoint],
  h_bold: &'static [EdwardsPoint],
}

include!(concat!(env!("OUT_DIR"), "/generators_plus.rs"));

impl BpPlusGenerators {
  #[allow(clippy::new_without_default)]
  pub(crate) fn new() -> Self {
    let gens = GENERATORS();
    BpPlusGenerators { g_bold: &gens.G, h_bold: &gens.H }
  }

  pub(crate) fn len(&self) -> usize {
    self.g_bold.len()
  }

  pub(crate) fn g() -> EdwardsPoint {
    H()
  }

  pub(crate) fn h() -> EdwardsPoint {
    ED25519_BASEPOINT_POINT
  }

  pub(crate) fn generator(&self, list: GeneratorsList, i: usize) -> EdwardsPoint {
    match list {
      GeneratorsList::GBold => self.g_bold[i],
      GeneratorsList::HBold => self.h_bold[i],
    }
  }

  pub(crate) fn reduce(&self, generators: usize) -> Self {
    // Round to the nearest power of 2
    let generators = padded_pow_of_2(generators);
    assert!(generators <= self.g_bold.len());

    BpPlusGenerators { g_bold: &self.g_bold[.. generators], h_bold: &self.h_bold[.. generators] }
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
