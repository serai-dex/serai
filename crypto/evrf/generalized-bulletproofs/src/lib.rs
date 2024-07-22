#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(non_snake_case)]

use core::fmt;
use std::collections::HashSet;

use zeroize::Zeroize;

use multiexp::{multiexp, multiexp_vartime};
use ciphersuite::{
  group::{ff::Field, Group, GroupEncoding},
  Ciphersuite,
};

mod scalar_vector;
pub use scalar_vector::ScalarVector;
mod point_vector;
pub use point_vector::PointVector;

/// The transcript formats.
pub mod transcript;

pub(crate) mod inner_product;

pub(crate) mod lincomb;

/// The arithmetic circuit proof.
pub mod arithmetic_circuit_proof;

/// Functionlity useful when testing.
#[cfg(any(test, feature = "tests"))]
pub mod tests;

/// Calculate the nearest power of two greater than or equivalent to the argument.
pub(crate) fn padded_pow_of_2(i: usize) -> usize {
  let mut next_pow_of_2 = 1;
  while next_pow_of_2 < i {
    next_pow_of_2 <<= 1;
  }
  next_pow_of_2
}

/// An error from working with generators.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum GeneratorsError {
  /// The provided list of generators for `g` (bold) was empty.
  GBoldEmpty,
  /// The provided list of generators for `h` (bold) did not match `g` (bold) in length.
  DifferingGhBoldLengths,
  /// The amount of provided generators were not a power of two.
  NotPowerOfTwo,
  /// A generator was used multiple times.
  DuplicatedGenerator,
}

/// A full set of generators.
#[derive(Clone)]
pub struct Generators<C: Ciphersuite> {
  g: C::G,
  h: C::G,

  g_bold: Vec<C::G>,
  h_bold: Vec<C::G>,
  h_sum: Vec<C::G>,
}

/// A batch verifier of proofs.
#[must_use]
pub struct BatchVerifier<C: Ciphersuite> {
  g: C::F,
  h: C::F,

  g_bold: Vec<C::F>,
  h_bold: Vec<C::F>,
  h_sum: Vec<C::F>,

  additional: Vec<(C::F, C::G)>,
}

impl<C: Ciphersuite> fmt::Debug for Generators<C> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    let g = self.g.to_bytes();
    let g: &[u8] = g.as_ref();

    let h = self.h.to_bytes();
    let h: &[u8] = h.as_ref();

    fmt.debug_struct("Generators").field("g", &g).field("h", &h).finish_non_exhaustive()
  }
}

/// The generators for a specific proof.
///
/// This potentially have been reduced in size from the original set of generators, as beneficial
/// to performance.
#[derive(Copy, Clone)]
pub struct ProofGenerators<'a, C: Ciphersuite> {
  g: &'a C::G,
  h: &'a C::G,

  g_bold: &'a [C::G],
  h_bold: &'a [C::G],
}

impl<C: Ciphersuite> fmt::Debug for ProofGenerators<'_, C> {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    let g = self.g.to_bytes();
    let g: &[u8] = g.as_ref();

    let h = self.h.to_bytes();
    let h: &[u8] = h.as_ref();

    fmt.debug_struct("ProofGenerators").field("g", &g).field("h", &h).finish_non_exhaustive()
  }
}

impl<C: Ciphersuite> Generators<C> {
  /// Construct an instance of Generators for usage with Bulletproofs.
  pub fn new(
    g: C::G,
    h: C::G,
    g_bold: Vec<C::G>,
    h_bold: Vec<C::G>,
  ) -> Result<Self, GeneratorsError> {
    if g_bold.is_empty() {
      Err(GeneratorsError::GBoldEmpty)?;
    }
    if g_bold.len() != h_bold.len() {
      Err(GeneratorsError::DifferingGhBoldLengths)?;
    }
    if padded_pow_of_2(g_bold.len()) != g_bold.len() {
      Err(GeneratorsError::NotPowerOfTwo)?;
    }

    let mut set = HashSet::new();
    let mut add_generator = |generator: &C::G| {
      assert!(!bool::from(generator.is_identity()));
      let bytes = generator.to_bytes();
      !set.insert(bytes.as_ref().to_vec())
    };

    assert!(!add_generator(&g), "g was prior present in empty set");
    if add_generator(&h) {
      Err(GeneratorsError::DuplicatedGenerator)?;
    }
    for g in &g_bold {
      if add_generator(g) {
        Err(GeneratorsError::DuplicatedGenerator)?;
      }
    }
    for h in &h_bold {
      if add_generator(h) {
        Err(GeneratorsError::DuplicatedGenerator)?;
      }
    }

    let mut running_h_sum = C::G::identity();
    let mut h_sum = vec![];
    let mut next_pow_of_2 = 1;
    for (i, h) in h_bold.iter().enumerate() {
      running_h_sum += h;
      if (i + 1) == next_pow_of_2 {
        h_sum.push(running_h_sum);
        next_pow_of_2 *= 2;
      }
    }

    Ok(Generators { g, h, g_bold, h_bold, h_sum })
  }

  /// Create a BatchVerifier for proofs which use these generators.
  pub fn batch_verifier(&self) -> BatchVerifier<C> {
    BatchVerifier {
      g: C::F::ZERO,
      h: C::F::ZERO,

      g_bold: vec![C::F::ZERO; self.g_bold.len()],
      h_bold: vec![C::F::ZERO; self.h_bold.len()],
      h_sum: vec![C::F::ZERO; self.h_sum.len()],

      additional: Vec::with_capacity(128),
    }
  }

  /// Verify all proofs queued for batch verification in this BatchVerifier.
  #[must_use]
  pub fn verify(&self, verifier: BatchVerifier<C>) -> bool {
    multiexp_vartime(
      &[(verifier.g, self.g), (verifier.h, self.h)]
        .into_iter()
        .chain(verifier.g_bold.into_iter().zip(self.g_bold.iter().cloned()))
        .chain(verifier.h_bold.into_iter().zip(self.h_bold.iter().cloned()))
        .chain(verifier.h_sum.into_iter().zip(self.h_sum.iter().cloned()))
        .chain(verifier.additional)
        .collect::<Vec<_>>(),
    )
    .is_identity()
    .into()
  }

  /// The `g` generator.
  pub fn g(&self) -> C::G {
    self.g
  }

  /// The `h` generator.
  pub fn h(&self) -> C::G {
    self.h
  }

  /// A slice to view the `g` (bold) generators.
  pub fn g_bold_slice(&self) -> &[C::G] {
    &self.g_bold
  }

  /// A slice to view the `h` (bold) generators.
  pub fn h_bold_slice(&self) -> &[C::G] {
    &self.h_bold
  }

  /// Reduce a set of generators to the quantity necessary to support a certain amount of
  /// in-circuit multiplications/terms in a Pedersen vector commitment.
  ///
  /// Returns None if reducing to 0 or if the generators reduced are insufficient to provide this
  /// many generators.
  pub fn reduce(&self, generators: usize) -> Option<ProofGenerators<'_, C>> {
    if generators == 0 {
      None?;
    }

    // Round to the nearest power of 2
    let generators = padded_pow_of_2(generators);
    if generators > self.g_bold.len() {
      None?;
    }

    Some(ProofGenerators {
      g: &self.g,
      h: &self.h,

      g_bold: &self.g_bold[.. generators],
      h_bold: &self.h_bold[.. generators],
    })
  }
}

impl<'a, C: Ciphersuite> ProofGenerators<'a, C> {
  pub(crate) fn len(&self) -> usize {
    self.g_bold.len()
  }

  pub(crate) fn g(&self) -> C::G {
    *self.g
  }

  pub(crate) fn h(&self) -> C::G {
    *self.h
  }

  pub(crate) fn g_bold(&self, i: usize) -> C::G {
    self.g_bold[i]
  }

  pub(crate) fn h_bold(&self, i: usize) -> C::G {
    self.h_bold[i]
  }

  pub(crate) fn g_bold_slice(&self) -> &[C::G] {
    self.g_bold
  }

  pub(crate) fn h_bold_slice(&self) -> &[C::G] {
    self.h_bold
  }
}

/// The opening of a Pedersen commitment.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct PedersenCommitment<C: Ciphersuite> {
  /// The value committed to.
  pub value: C::F,
  /// The mask blinding the value committed to.
  pub mask: C::F,
}

impl<C: Ciphersuite> PedersenCommitment<C> {
  /// Commit to this value, yielding the Pedersen commitment.
  pub fn commit(&self, g: C::G, h: C::G) -> C::G {
    multiexp(&[(self.value, g), (self.mask, h)])
  }
}

/// The opening of a Pedersen vector commitment.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct PedersenVectorCommitment<C: Ciphersuite> {
  /// The values committed to across the `g` (bold) generators.
  pub g_values: ScalarVector<C::F>,
  /// The values committed to across the `h` (bold) generators.
  pub h_values: ScalarVector<C::F>,
  /// The mask blinding the values committed to.
  pub mask: C::F,
}

impl<C: Ciphersuite> PedersenVectorCommitment<C> {
  /// Commit to the vectors of values.
  ///
  /// This function returns None if the amount of generators is less than the amount of values
  /// within the relevant vector.
  pub fn commit(&self, g_bold: &[C::G], h_bold: &[C::G], h: C::G) -> Option<C::G> {
    if (g_bold.len() < self.g_values.len()) || (h_bold.len() < self.h_values.len()) {
      None?;
    };

    let mut terms = vec![(self.mask, h)];
    for pair in self.g_values.0.iter().cloned().zip(g_bold.iter().cloned()) {
      terms.push(pair);
    }
    for pair in self.h_values.0.iter().cloned().zip(h_bold.iter().cloned()) {
      terms.push(pair);
    }
    let res = multiexp(&terms);
    terms.zeroize();
    Some(res)
  }
}
