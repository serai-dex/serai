#![allow(non_snake_case)]

use std::collections::{HashSet, HashMap};

use zeroize::{Zeroize, ZeroizeOnDrop};

use rand_core::{RngCore, CryptoRng};

use transcript::Transcript;
use multiexp::{multiexp_vartime, Point as MultiexpPoint};
use ciphersuite::{
  group::{ff::Field, Group, GroupEncoding},
  Ciphersuite,
};

mod scalar_vector;
pub use scalar_vector::{ScalarVector, weighted_inner_product};
mod scalar_matrix;
pub use scalar_matrix::ScalarMatrix;
mod point_vector;
pub use point_vector::PointVector;

pub mod weighted_inner_product;
pub mod single_range_proof;
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

// TODO: Table these
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct VectorCommitmentGenerators<T: 'static + Transcript, C: Ciphersuite> {
  generators: Vec<MultiexpPoint<C::G>>,
  transcript: T::Challenge,
}

impl<T: 'static + Transcript, C: Ciphersuite> VectorCommitmentGenerators<T, C> {
  pub fn new(generators: &[C::G]) -> Self {
    assert!(!generators.is_empty());

    let mut transcript = T::new(b"Bulletproofs+ Vector Commitments Generators");

    transcript.domain_separate(b"generators");
    let mut res = vec![];
    let mut set = HashSet::new();
    let mut add_generator = |generator: &C::G| {
      assert!(!bool::from(generator.is_identity()));
      res.push(MultiexpPoint::new_constant(*generator));
      let bytes = generator.to_bytes();
      transcript.append_message(b"generator", bytes.as_ref());
      assert!(set.insert(bytes.as_ref().to_vec()));
    };

    for generator in generators {
      add_generator(generator);
    }

    Self { generators: res, transcript: transcript.challenge(b"summary") }
  }

  #[allow(clippy::len_without_is_empty)] // Generators should never be empty/potentially empty
  pub fn len(&self) -> usize {
    self.generators.len()
  }

  pub fn generators(&self) -> &[MultiexpPoint<C::G>] {
    &self.generators
  }

  pub fn transcript(&self) -> &T::Challenge {
    &self.transcript
  }

  pub fn commit_vartime(&self, vars: &[C::F]) -> C::G {
    assert_eq!(self.len(), vars.len());

    let mut multiexp = vec![];
    for (var, point) in vars.iter().zip(self.generators().iter()) {
      multiexp.push((*var, point.point()));
    }
    multiexp_vartime(&multiexp)
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) enum GeneratorsList {
  GBold1,
  GBold2,
  HBold1,
  HBold2,
}

// TODO: Should these all be static? Should MultiexpPoint itself work off &'static references?
// TODO: Table these
#[derive(Clone, Debug)]
pub struct Generators<T: 'static + Transcript, C: Ciphersuite> {
  g: MultiexpPoint<C::G>,
  h: MultiexpPoint<C::G>,

  g_bold1: Vec<MultiexpPoint<C::G>>,
  h_bold1: Vec<MultiexpPoint<C::G>>,

  proving_gs: Option<(MultiexpPoint<C::G>, MultiexpPoint<C::G>)>,
  proving_h_bolds: Option<(Vec<MultiexpPoint<C::G>>, Vec<MultiexpPoint<C::G>>)>,

  whitelisted_vector_commitments: HashSet<Vec<u8>>,
  // Uses a Vec<u8> since C::G doesn't impl Hash
  set: HashSet<Vec<u8>>,
  transcript: T,
}

#[derive(Clone, Debug)]
pub struct ProofGenerators<'a, T: 'static + Transcript, C: Ciphersuite> {
  g: &'a MultiexpPoint<C::G>,
  h: &'a MultiexpPoint<C::G>,

  g_bold1: &'a [MultiexpPoint<C::G>],
  h_bold1: &'a [MultiexpPoint<C::G>],

  proving_gs: Option<&'a (MultiexpPoint<C::G>, MultiexpPoint<C::G>)>,
  proving_h_bolds: Option<(&'a [MultiexpPoint<C::G>], &'a [MultiexpPoint<C::G>])>,

  whitelisted_vector_commitments: &'a HashSet<Vec<u8>>,
  transcript: T,

  replaced: HashMap<(GeneratorsList, usize), MultiexpPoint<C::G>>,
}

#[derive(Clone, Debug)]
pub struct InnerProductGenerators<
  'a,
  T: 'static + Transcript,
  C: Ciphersuite,
  GB: Clone + AsRef<[MultiexpPoint<C::G>]>,
> {
  g: &'a MultiexpPoint<C::G>,
  h: &'a MultiexpPoint<C::G>,

  g_bold1: GB,
  h_bold1: &'a [MultiexpPoint<C::G>],
  replaced: HashMap<(GeneratorsList, usize), MultiexpPoint<C::G>>,

  transcript: T,
}

impl<T: 'static + Transcript, C: Ciphersuite> Generators<T, C> {
  pub fn new(
    g: C::G,
    h: C::G,
    mut g_bold1: Vec<C::G>,
    mut h_bold1: Vec<C::G>,
  ) -> Self {
    assert!(!g_bold1.is_empty());
    assert_eq!(g_bold1.len(), h_bold1.len());

    assert_eq!(padded_pow_of_2(g_bold1.len()), g_bold1.len(), "generators must be a pow of 2");

    let mut transcript = T::new(b"Bulletproofs+ Generators");

    transcript.domain_separate(b"generators");
    let mut set = HashSet::new();
    let mut add_generator = |label, generator: &C::G| {
      assert!(!bool::from(generator.is_identity()));
      let bytes = generator.to_bytes();
      transcript.append_message(label, bytes);
      assert!(set.insert(bytes.as_ref().to_vec()));
    };

    add_generator(b"g", &g);
    add_generator(b"h", &h);
    for g in &g_bold1 {
      add_generator(b"g_bold1", g);
    }
    for h in &h_bold1 {
      add_generator(b"h_bold1", h);
    }

    Generators {
      g: MultiexpPoint::new_constant(g),
      h: MultiexpPoint::new_constant(h),

      g_bold1: g_bold1.drain(..).map(MultiexpPoint::new_constant).collect(),
      h_bold1: h_bold1.drain(..).map(MultiexpPoint::new_constant).collect(),

      proving_gs: None,
      proving_h_bolds: None,

      set,
      whitelisted_vector_commitments: HashSet::new(),
      transcript,
    }
  }

  pub fn g(&self) -> &MultiexpPoint<C::G> {
    &self.g
  }

  pub fn h(&self) -> &MultiexpPoint<C::G> {
    &self.h
  }

  /// Take a presumably global Generators object and return a new object usable per-proof.
  ///
  /// Cloning Generators is expensive. This solely takes references to the generators.
  pub fn per_proof(&self) -> ProofGenerators<'_, T, C> {
    ProofGenerators {
      g: &self.g,
      h: &self.h,

      g_bold1: &self.g_bold1,
      h_bold1: &self.h_bold1,

      transcript: self.transcript.clone(),
    }
  }
}

impl<'a, T: 'static + Transcript, C: Ciphersuite> ProofGenerators<'a, T, C> {
  pub fn g(&self) -> &MultiexpPoint<C::G> {
    self.g
  }

  pub fn h(&self) -> &MultiexpPoint<C::G> {
    self.h
  }

  pub(crate) fn generator(&self, list: GeneratorsList, i: usize) -> &MultiexpPoint<C::G> {
    self.replaced.get(&(list, i)).unwrap_or_else(|| {
      &(match list {
        GeneratorsList::GBold1 => self.g_bold1,
        GeneratorsList::HBold1 => self.h_bold1,
      }[i])
    })
  }

  pub(crate) fn reduce(
    mut self,
    generators: usize,
    with_secondaries: bool,
  ) -> InnerProductGenerators<'a, T, C, &'a [MultiexpPoint<C::G>]> {
    // Round to the nearest power of 2
    let generators = padded_pow_of_2(generators);
    assert!(generators <= self.g_bold1.len());

    self.g_bold1 = &self.g_bold1[.. generators];
    self.h_bold1 = &self.h_bold1[.. generators];
    self
      .transcript
      .append_message(b"used_generators", u32::try_from(generators).unwrap().to_le_bytes());

    if with_secondaries {
      self.transcript.append_message(b"secondaries", b"true");
      InnerProductGenerators {
        g: self.g,
        h: self.h,

        g_bold1: self.g_bold1,
        h_bold1: self.h_bold1,

        // TODO: Can this be replaced with just a challenge?
        transcript: self.transcript.clone(),
      }
    } else {
      self.transcript.append_message(b"secondaries", b"false");
      InnerProductGenerators {
        g: self.g,
        h: self.h,

        g_bold1: self.g_bold1,
        h_bold1: self.h_bold1,

        transcript: self.transcript.clone(),
      }
    }
  }
}

impl<'a, T: 'static + Transcript, C: Ciphersuite, GB: Clone + AsRef<[MultiexpPoint<C::G>]>>
  InnerProductGenerators<'a, T, C, GB>
{
  pub(crate) fn len(&self) -> usize {
    self.g_bold1.as_ref().len()
  }

  pub(crate) fn g(&self) -> &MultiexpPoint<C::G> {
    self.g
  }

  pub(crate) fn h(&self) -> &MultiexpPoint<C::G> {
    self.h
  }

  pub(crate) fn generator(&self, mut list: GeneratorsList, mut i: usize) -> &MultiexpPoint<C::G> {
    match list {
      GeneratorsList::GBold1 => self.g_bold1[i],
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
