use core::ops::{Index, IndexMut, Add, Sub, Mul};

use zeroize::Zeroize;

use ciphersuite::group::ff::PrimeField;

/// A scalar vector struct with the functionality necessary for Bulletproofs.
///
/// The math operations for this panic upon any invalid operation, such as if vectors of different
/// lengths are added. The full extent of invalidity is not fully defined. Only `new`, `len`,
/// and field access is guaranteed to have a safe, public API.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ScalarVector<F: PrimeField>(pub(crate) Vec<F>);

impl<F: PrimeField + Zeroize> Zeroize for ScalarVector<F> {
  fn zeroize(&mut self) {
    self.0.zeroize()
  }
}

impl<F: PrimeField> Index<usize> for ScalarVector<F> {
  type Output = F;
  fn index(&self, index: usize) -> &F {
    &self.0[index]
  }
}
impl<F: PrimeField> IndexMut<usize> for ScalarVector<F> {
  fn index_mut(&mut self, index: usize) -> &mut F {
    &mut self.0[index]
  }
}

impl<F: PrimeField> Add<F> for ScalarVector<F> {
  type Output = ScalarVector<F>;
  fn add(mut self, scalar: F) -> Self {
    for s in &mut self.0 {
      *s += scalar;
    }
    self
  }
}
impl<F: PrimeField> Sub<F> for ScalarVector<F> {
  type Output = ScalarVector<F>;
  fn sub(mut self, scalar: F) -> Self {
    for s in &mut self.0 {
      *s -= scalar;
    }
    self
  }
}
impl<F: PrimeField> Mul<F> for ScalarVector<F> {
  type Output = ScalarVector<F>;
  fn mul(mut self, scalar: F) -> Self {
    for s in &mut self.0 {
      *s *= scalar;
    }
    self
  }
}

impl<F: PrimeField> Add<&ScalarVector<F>> for ScalarVector<F> {
  type Output = ScalarVector<F>;
  fn add(mut self, other: &ScalarVector<F>) -> Self {
    assert_eq!(self.len(), other.len());
    for (s, o) in self.0.iter_mut().zip(other.0.iter()) {
      *s += o;
    }
    self
  }
}
impl<F: PrimeField> Sub<&ScalarVector<F>> for ScalarVector<F> {
  type Output = ScalarVector<F>;
  fn sub(mut self, other: &ScalarVector<F>) -> Self {
    assert_eq!(self.len(), other.len());
    for (s, o) in self.0.iter_mut().zip(other.0.iter()) {
      *s -= o;
    }
    self
  }
}
impl<F: PrimeField> Mul<&ScalarVector<F>> for ScalarVector<F> {
  type Output = ScalarVector<F>;
  fn mul(mut self, other: &ScalarVector<F>) -> Self {
    assert_eq!(self.len(), other.len());
    for (s, o) in self.0.iter_mut().zip(other.0.iter()) {
      *s *= o;
    }
    self
  }
}

impl<F: PrimeField> ScalarVector<F> {
  /// Create a new scalar vector, initialized with `len` zero scalars.
  pub fn new(len: usize) -> Self {
    ScalarVector(vec![F::ZERO; len])
  }

  pub(crate) fn powers(x: F, len: usize) -> Self {
    assert!(len != 0);

    let mut res = Vec::with_capacity(len);
    res.push(F::ONE);
    res.push(x);
    for i in 2 .. len {
      res.push(res[i - 1] * x);
    }
    res.truncate(len);
    ScalarVector(res)
  }

  /// The length of this scalar vector.
  #[allow(clippy::len_without_is_empty)]
  pub fn len(&self) -> usize {
    self.0.len()
  }

  /*
  pub(crate) fn sum(mut self) -> F {
    self.0.drain(..).sum()
  }
  */

  pub(crate) fn inner_product<'a, V: Iterator<Item = &'a F>>(&self, vector: V) -> F {
    let mut count = 0;
    let mut res = F::ZERO;
    for (a, b) in self.0.iter().zip(vector) {
      res += *a * b;
      count += 1;
    }
    debug_assert_eq!(self.len(), count);
    res
  }

  pub(crate) fn split(mut self) -> (Self, Self) {
    assert!(self.len() > 1);
    let r = self.0.split_off(self.0.len() / 2);
    debug_assert_eq!(self.len(), r.len());
    (self, ScalarVector(r))
  }
}

impl<F: PrimeField> From<Vec<F>> for ScalarVector<F> {
  fn from(vec: Vec<F>) -> Self {
    Self(vec)
  }
}
