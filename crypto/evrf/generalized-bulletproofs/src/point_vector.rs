use core::ops::{Index, IndexMut};

use zeroize::Zeroize;

use ciphersuite::Ciphersuite;

#[cfg(test)]
use multiexp::multiexp;

use crate::ScalarVector;

/// A point vector struct with the functionality necessary for Bulletproofs.
///
/// The math operations for this panic upon any invalid operation, such as if vectors of different
/// lengths are added. The full extent of invalidity is not fully defined. Only field access is
/// guaranteed to have a safe, public API.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct PointVector<C: Ciphersuite>(pub(crate) Vec<C::G>);

impl<C: Ciphersuite> Index<usize> for PointVector<C> {
  type Output = C::G;
  fn index(&self, index: usize) -> &C::G {
    &self.0[index]
  }
}

impl<C: Ciphersuite> IndexMut<usize> for PointVector<C> {
  fn index_mut(&mut self, index: usize) -> &mut C::G {
    &mut self.0[index]
  }
}

impl<C: Ciphersuite> PointVector<C> {
  /*
  pub(crate) fn add(&self, point: impl AsRef<C::G>) -> Self {
    let mut res = self.clone();
    for val in res.0.iter_mut() {
      *val += point.as_ref();
    }
    res
  }
  pub(crate) fn sub(&self, point: impl AsRef<C::G>) -> Self {
    let mut res = self.clone();
    for val in res.0.iter_mut() {
      *val -= point.as_ref();
    }
    res
  }

  pub(crate) fn mul(&self, scalar: impl core::borrow::Borrow<C::F>) -> Self {
    let mut res = self.clone();
    for val in res.0.iter_mut() {
      *val *= scalar.borrow();
    }
    res
  }

  pub(crate) fn add_vec(&self, vector: &Self) -> Self {
    debug_assert_eq!(self.len(), vector.len());
    let mut res = self.clone();
    for (i, val) in res.0.iter_mut().enumerate() {
      *val += vector.0[i];
    }
    res
  }

  pub(crate) fn sub_vec(&self, vector: &Self) -> Self {
    debug_assert_eq!(self.len(), vector.len());
    let mut res = self.clone();
    for (i, val) in res.0.iter_mut().enumerate() {
      *val -= vector.0[i];
    }
    res
  }
  */

  pub(crate) fn mul_vec(&self, vector: &ScalarVector<C::F>) -> Self {
    debug_assert_eq!(self.len(), vector.len());
    let mut res = self.clone();
    for (i, val) in res.0.iter_mut().enumerate() {
      *val *= vector.0[i];
    }
    res
  }

  #[cfg(test)]
  pub(crate) fn multiexp(&self, vector: &crate::ScalarVector<C::F>) -> C::G {
    debug_assert_eq!(self.len(), vector.len());
    let mut res = Vec::with_capacity(self.len());
    for (point, scalar) in self.0.iter().copied().zip(vector.0.iter().copied()) {
      res.push((scalar, point));
    }
    multiexp(&res)
  }

  /*
  pub(crate) fn multiexp_vartime(&self, vector: &ScalarVector<C::F>) -> C::G {
    debug_assert_eq!(self.len(), vector.len());
    let mut res = Vec::with_capacity(self.len());
    for (point, scalar) in self.0.iter().copied().zip(vector.0.iter().copied()) {
      res.push((scalar, point));
    }
    multiexp_vartime(&res)
  }

  pub(crate) fn sum(&self) -> C::G {
    self.0.iter().sum()
  }
  */

  pub(crate) fn len(&self) -> usize {
    self.0.len()
  }

  pub(crate) fn split(mut self) -> (Self, Self) {
    assert!(self.len() > 1);
    let r = self.0.split_off(self.0.len() / 2);
    debug_assert_eq!(self.len(), r.len());
    (self, PointVector(r))
  }
}
