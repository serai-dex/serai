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

pub(crate) mod arithmetic_circuit_proof;
pub mod arithmetic_circuit;
pub mod gadgets;

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
  g_bold2: Vec<MultiexpPoint<C::G>>,
  h_bold1: Vec<MultiexpPoint<C::G>>,
  h_bold2: Vec<MultiexpPoint<C::G>>,

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
  g_bold2: &'a [MultiexpPoint<C::G>],
  h_bold1: &'a [MultiexpPoint<C::G>],
  h_bold2: &'a [MultiexpPoint<C::G>],

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
  g_bold2: &'a [MultiexpPoint<C::G>],
  h_bold1: &'a [MultiexpPoint<C::G>],
  h_bold2: &'a [MultiexpPoint<C::G>],
  replaced: HashMap<(GeneratorsList, usize), MultiexpPoint<C::G>>,

  transcript: T,
}

impl<T: 'static + Transcript, C: Ciphersuite> Generators<T, C> {
  pub fn new(
    g: C::G,
    h: C::G,
    mut g_bold1: Vec<C::G>,
    mut g_bold2: Vec<C::G>,
    mut h_bold1: Vec<C::G>,
    mut h_bold2: Vec<C::G>,
  ) -> Self {
    assert!(!g_bold1.is_empty());
    assert_eq!(g_bold1.len(), g_bold2.len());
    assert_eq!(h_bold1.len(), h_bold2.len());
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
    for g in &g_bold2 {
      add_generator(b"g_bold2", g);
    }
    for h in &h_bold1 {
      add_generator(b"h_bold1", h);
    }
    for h in &h_bold2 {
      add_generator(b"h_bold2", h);
    }

    Generators {
      g: MultiexpPoint::new_constant(g),
      h: MultiexpPoint::new_constant(h),

      g_bold1: g_bold1.drain(..).map(MultiexpPoint::new_constant).collect(),
      g_bold2: g_bold2.drain(..).map(MultiexpPoint::new_constant).collect(),
      h_bold1: h_bold1.drain(..).map(MultiexpPoint::new_constant).collect(),
      h_bold2: h_bold2.drain(..).map(MultiexpPoint::new_constant).collect(),

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

  /// Add generators used for proving the vector commitments' validity.
  // TODO: Remove when we get a proper VC scheme
  pub fn add_vector_commitment_proving_generators(
    &mut self,
    gs: (C::G, C::G),
    mut h_bold1: (Vec<C::G>, Vec<C::G>),
  ) {
    assert!(self.proving_gs.is_none());

    assert_eq!(h_bold1.0.len(), h_bold1.1.len());

    self.transcript.domain_separate(b"vector_commitment_proving_generators");

    let mut add_generator = |label, generator: &C::G| {
      assert!(!bool::from(generator.is_identity()));
      let bytes = generator.to_bytes();
      self.transcript.append_message(label, bytes.as_ref());
      assert!(self.set.insert(bytes.as_ref().to_vec()));
    };

    add_generator(b"g0", &gs.0);
    add_generator(b"g1", &gs.1);

    for h_bold in &h_bold1.0 {
      add_generator(b"h_bold0", h_bold);
    }
    for h_bold in &h_bold1.1 {
      add_generator(b"h_bold1", h_bold);
    }

    self.proving_gs = Some((MultiexpPoint::new_constant(gs.0), MultiexpPoint::new_constant(gs.1)));
    self.proving_h_bolds = Some((
      h_bold1.0.drain(..).map(MultiexpPoint::new_constant).collect(),
      h_bold1.1.drain(..).map(MultiexpPoint::new_constant).collect(),
    ));
  }

  /// Whitelist a series of vector commitments generators.
  ///
  /// Used to ensure a lack of overlap between Generators and VectorCommitmentGenerators.
  pub fn whitelist_vector_commitments(
    &mut self,
    label: &'static [u8],
    generators: &VectorCommitmentGenerators<T, C>,
  ) {
    assert!(self.proving_gs.is_some());

    for generator in &generators.generators {
      let MultiexpPoint::Constant(bytes, _) = generator else { unreachable!() };
      assert!(self.set.insert(bytes.to_vec()));
    }

    self.transcript.domain_separate(b"vector_commitment_generators");
    self.transcript.append_message(label, generators.transcript.as_ref());
    assert!(self.whitelisted_vector_commitments.insert(generators.transcript.as_ref().to_vec()));
  }

  /// Take a presumably global Generators object and return a new object usable per-proof.
  ///
  /// Cloning Generators is expensive. This solely takes references to the generators.
  pub fn per_proof(&self) -> ProofGenerators<'_, T, C> {
    ProofGenerators {
      g: &self.g,
      h: &self.h,

      g_bold1: &self.g_bold1,
      g_bold2: &self.g_bold2,
      h_bold1: &self.h_bold1,
      h_bold2: &self.h_bold2,

      proving_gs: self.proving_gs.as_ref(),
      proving_h_bolds: self.proving_h_bolds.as_ref().map(|(h1, h2)| (h1.as_slice(), h2.as_slice())),

      whitelisted_vector_commitments: &self.whitelisted_vector_commitments,
      transcript: self.transcript.clone(),

      replaced: HashMap::new(),
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

  pub(crate) fn replace_generators(
    &mut self,
    from: &VectorCommitmentGenerators<T, C>,
    mut to_replace: Vec<(GeneratorsList, usize)>,
  ) {
    debug_assert!(self.whitelisted_vector_commitments.contains(from.transcript.as_ref()));

    assert_eq!(from.generators.len(), to_replace.len());

    self.transcript.domain_separate(b"replaced_generators");
    self.transcript.append_message(b"from", from.transcript.as_ref());

    for (i, (list, index)) in to_replace.drain(..).enumerate() {
      self.transcript.append_message(
        b"list",
        match list {
          GeneratorsList::GBold1 => b"g_bold1",
          GeneratorsList::GBold2 => b"g_bold2",
          GeneratorsList::HBold1 => b"h_bold1",
          GeneratorsList::HBold2 => panic!("vector commitments had h_bold2"),
        },
      );
      self.transcript.append_message(b"index", u32::try_from(index).unwrap().to_le_bytes());

      // TODO: Should replaced be &MultiexpPoint<C::G>?
      assert!(self.replaced.insert((list, index), from.generators[i].clone()).is_none());
    }
  }

  pub(crate) fn generator(&self, list: GeneratorsList, i: usize) -> &MultiexpPoint<C::G> {
    self.replaced.get(&(list, i)).unwrap_or_else(|| {
      &(match list {
        GeneratorsList::GBold1 => self.g_bold1,
        GeneratorsList::GBold2 => self.g_bold2,
        GeneratorsList::HBold1 => self.h_bold1,
        GeneratorsList::HBold2 => self.h_bold2,
      }[i])
    })
  }

  pub(crate) fn vector_commitment_generators(
    &self,
    vc_generators: Vec<(GeneratorsList, usize)>,
  ) -> (
    InnerProductGenerators<'a, T, C, Vec<MultiexpPoint<C::G>>>,
    InnerProductGenerators<'a, T, C, Vec<MultiexpPoint<C::G>>>,
  ) {
    let gs = self.proving_gs.unwrap();
    let (h_bold0, h_bold1) = self.proving_h_bolds.unwrap();

    let mut g_bold1 = vec![];
    let mut transcript = self.transcript.clone();
    transcript.domain_separate(b"vector_commitment_proving_generators");
    for (list, i) in vc_generators {
      transcript.append_message(
        b"list",
        match list {
          GeneratorsList::GBold1 => {
            g_bold1.push(self.generator(list, i).clone());
            b"g_bold1"
          }
          GeneratorsList::HBold1 => {
            g_bold1.push(self.generator(list, i).clone());
            b"h_bold1"
          }
          GeneratorsList::GBold2 => {
            g_bold1.push(self.generator(list, i).clone());
            b"g_bold2"
          }
          GeneratorsList::HBold2 => panic!("vector commitments had h_bold2"),
        },
      );
      transcript
        .append_message(b"vector_commitment_generator", u32::try_from(i).unwrap().to_le_bytes());
    }

    let pow_2 = padded_pow_of_2(g_bold1.len());
    let needed_for_pow_2 = pow_2 - g_bold1.len();
    assert!(h_bold0.len() >= (pow_2 + needed_for_pow_2));
    let mut g_bold1_0 = g_bold1.clone();
    let mut g_bold1_1 = g_bold1;
    for i in 0 .. needed_for_pow_2 {
      g_bold1_0.push(h_bold0[i].clone());
      g_bold1_1.push(h_bold1[i].clone());
    }

    let mut generators_0 = InnerProductGenerators {
      g: &gs.0,
      h: self.h,

      g_bold1: g_bold1_0,
      h_bold1: &h_bold0[needed_for_pow_2 .. (pow_2 + needed_for_pow_2)],
      g_bold2: &[],
      h_bold2: &[],
      replaced: HashMap::new(),

      transcript: transcript.clone(),
    };
    generators_0.transcript.append_message(b"generators", "0");

    let mut generators_1 = InnerProductGenerators {
      g: &gs.1,
      h: self.h,

      g_bold1: g_bold1_1,
      h_bold1: &h_bold1[needed_for_pow_2 .. (pow_2 + needed_for_pow_2)],
      g_bold2: &[],
      h_bold2: &[],
      replaced: HashMap::new(),

      transcript,
    };
    generators_1.transcript.append_message(b"generators", "1");

    (generators_0, generators_1)
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
    self.g_bold2 = &self.g_bold2[.. generators];
    self.h_bold1 = &self.h_bold1[.. generators];
    self.h_bold2 = &self.h_bold2[.. generators];
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
        g_bold2: self.g_bold2,
        h_bold2: self.h_bold2,
        // TODO: Should this be Arc RwLock?
        replaced: self.replaced.clone(),

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
        g_bold2: &[],
        h_bold2: &[],
        replaced: self.replaced.clone(),

        transcript: self.transcript.clone(),
      }
    }
  }
}

impl<'a, T: 'static + Transcript, C: Ciphersuite, GB: Clone + AsRef<[MultiexpPoint<C::G>]>>
  InnerProductGenerators<'a, T, C, GB>
{
  pub(crate) fn len(&self) -> usize {
    self.g_bold1.as_ref().len() + self.g_bold2.len()
  }

  pub(crate) fn g(&self) -> &MultiexpPoint<C::G> {
    self.g
  }

  pub(crate) fn h(&self) -> &MultiexpPoint<C::G> {
    self.h
  }

  // TODO: Replace with g_bold + h_bold
  pub(crate) fn generator(&self, mut list: GeneratorsList, mut i: usize) -> &MultiexpPoint<C::G> {
    if i >= self.g_bold1.as_ref().len() {
      i -= self.g_bold1.as_ref().len();
      list = match list {
        GeneratorsList::GBold1 => GeneratorsList::GBold2,
        GeneratorsList::HBold1 => GeneratorsList::HBold2,
        _ => panic!("InnerProductGenerators asked for g_bold2/h_bold2"),
      };
    }

    // TODO: What's the safety of this? replaced hasn't been updated for the reduction
    // No generators above the truncation *should* have been replaced, and it's an error if so
    self.replaced.get(&(list, i)).unwrap_or(
      &(match list {
        GeneratorsList::GBold1 => self.g_bold1.as_ref(),
        GeneratorsList::GBold2 => self.g_bold2,
        GeneratorsList::HBold1 => self.h_bold1,
        GeneratorsList::HBold2 => self.h_bold2,
      })[i],
    )
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
