#![allow(non_snake_case)]

use group::Group;
use dalek_ff_group::{Scalar, EdwardsPoint};

mod scalar_vector;
pub(crate) use scalar_vector::{ScalarVector, weighted_inner_product};
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
  GBold1,
  HBold1,
}

// TODO: Table these
#[derive(Clone, Debug)]
pub(crate) struct Generators {
  g_bold1: &'static [EdwardsPoint],
  h_bold1: &'static [EdwardsPoint],
}

mod generators {
  use std_shims::sync::OnceLock;
  use monero_generators::Generators;
  include!(concat!(env!("OUT_DIR"), "/generators_plus.rs"));
}

impl Generators {
  #[allow(clippy::new_without_default)]
  pub(crate) fn new() -> Self {
    let gens = generators::GENERATORS();
    Generators { g_bold1: &gens.G, h_bold1: &gens.H }
  }

  pub(crate) fn len(&self) -> usize {
    self.g_bold1.len()
  }

  pub(crate) fn g() -> EdwardsPoint {
    dalek_ff_group::EdwardsPoint(crate::H())
  }

  pub(crate) fn h() -> EdwardsPoint {
    EdwardsPoint::generator()
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

    Generators { g_bold1: &self.g_bold1[.. generators], h_bold1: &self.h_bold1[.. generators] }
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
