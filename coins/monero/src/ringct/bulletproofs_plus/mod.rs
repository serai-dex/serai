#![allow(non_snake_case)]

use std::collections::{HashSet, HashMap};

use zeroize::{Zeroize, ZeroizeOnDrop};

use rand_core::{RngCore, CryptoRng};

use multiexp::multiexp_vartime;
use ciphersuite::{
  group::{ff::Field, Group, GroupEncoding},
  Ciphersuite,
};

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
pub struct Generators<C: Ciphersuite> {
  g: C::G,
  h: C::G,

  g_bold1: Vec<C::G>,
  h_bold1: Vec<C::G>,
}

#[derive(Clone, Debug)]
pub struct ProofGenerators<'a, C: Ciphersuite> {
  g: &'a C::G,
  h: &'a C::G,

  g_bold1: &'a [C::G],
  h_bold1: &'a [C::G],
}

#[derive(Clone, Debug)]
pub struct InnerProductGenerators<'a, C: Ciphersuite, GB: Clone + AsRef<[C::G]>> {
  g: &'a C::G,
  h: &'a C::G,

  g_bold1: GB,
  h_bold1: &'a [C::G],
}

impl<C: Ciphersuite> Generators<C> {
  pub fn new(g: C::G, h: C::G, mut g_bold1: Vec<C::G>, mut h_bold1: Vec<C::G>) -> Self {
    assert!(!g_bold1.is_empty());
    assert_eq!(g_bold1.len(), h_bold1.len());

    assert_eq!(padded_pow_of_2(g_bold1.len()), g_bold1.len(), "generators must be a pow of 2");

    Generators { g, h, g_bold1, h_bold1 }
  }

  pub fn g(&self) -> C::G {
    self.g
  }

  pub fn h(&self) -> C::G {
    self.h
  }

  /// Take a presumably global Generators object and return a new object usable per-proof.
  ///
  /// Cloning Generators is expensive. This solely takes references to the generators.
  pub fn per_proof(&self) -> ProofGenerators<'_, C> {
    ProofGenerators { g: &self.g, h: &self.h, g_bold1: &self.g_bold1, h_bold1: &self.h_bold1 }
  }
}

impl<'a, C: Ciphersuite> ProofGenerators<'a, C> {
  pub fn g(&self) -> C::G {
    *self.g
  }

  pub fn h(&self) -> C::G {
    *self.h
  }

  pub(crate) fn generator(&self, list: GeneratorsList, i: usize) -> C::G {
    match list {
      GeneratorsList::GBold1 => self.g_bold1[i],
      GeneratorsList::HBold1 => self.h_bold1[i],
    }
  }

  pub(crate) fn reduce(
    mut self,
    generators: usize,
    with_secondaries: bool,
  ) -> InnerProductGenerators<'a, C, &'a [C::G]> {
    // Round to the nearest power of 2
    let generators = padded_pow_of_2(generators);
    assert!(generators <= self.g_bold1.len());

    self.g_bold1 = &self.g_bold1[.. generators];
    self.h_bold1 = &self.h_bold1[.. generators];

    InnerProductGenerators { g: self.g, h: self.h, g_bold1: self.g_bold1, h_bold1: self.h_bold1 }
  }
}

impl<'a, C: Ciphersuite, GB: Clone + AsRef<[C::G]>> InnerProductGenerators<'a, C, GB> {
  pub(crate) fn len(&self) -> usize {
    self.g_bold1.as_ref().len()
  }

  pub(crate) fn g(&self) -> C::G {
    *self.g
  }

  pub(crate) fn h(&self) -> C::G {
    *self.h
  }

  pub(crate) fn generator(&self, mut list: GeneratorsList, mut i: usize) -> C::G {
    match list {
      GeneratorsList::GBold1 => self.g_bold1.as_ref()[i],
      GeneratorsList::HBold1 => self.h_bold1[i],
    }
  }
}

// Range proof structures

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct RangeCommitment<C: Ciphersuite> {
  pub value: u64,
  pub mask: C::F,
}

impl<C: Ciphersuite> RangeCommitment<C> {
  pub fn zero() -> Self {
    RangeCommitment { value: 0, mask: C::F::ZERO }
  }

  pub fn new(value: u64, mask: C::F) -> Self {
    RangeCommitment { value, mask }
  }

  pub fn masking<R: RngCore + CryptoRng>(rng: &mut R, value: u64) -> Self {
    RangeCommitment { value, mask: C::F::random(rng) }
  }

  /// Calculate a Pedersen commitment, as a point, from the transparent structure.
  pub fn calculate(&self, g: C::G, h: C::G) -> C::G {
    (g * C::F::from(self.value)) + (h * self.mask)
  }
}

// Returns the little-endian decomposition.
fn u64_decompose<C: Ciphersuite>(value: u64) -> ScalarVector<C> {
  let mut bits = ScalarVector::<C>::new(64);
  for bit in 0 .. 64 {
    bits[bit] = C::F::from((value >> bit) & 1);
  }
  bits
}
