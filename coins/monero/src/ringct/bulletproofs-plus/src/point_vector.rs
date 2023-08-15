use core::ops::{Index, IndexMut};

use zeroize::{Zeroize, ZeroizeOnDrop};

use transcript::Transcript;

use ciphersuite::{group::GroupEncoding, Ciphersuite};

#[cfg(test)]
use multiexp::multiexp;
#[cfg(test)]
use crate::ScalarVector;

#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PointVector<C: Ciphersuite>(pub Vec<C::G>);

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
    assert_eq!(self.len(), vector.len());
    let mut res = self.clone();
    for (i, val) in res.0.iter_mut().enumerate() {
      *val += vector.0[i];
    }
    res
  }

  pub(crate) fn sub_vec(&self, vector: &Self) -> Self {
    assert_eq!(self.len(), vector.len());
    let mut res = self.clone();
    for (i, val) in res.0.iter_mut().enumerate() {
      *val -= vector.0[i];
    }
    res
  }

  pub(crate) fn mul_vec(&self, vector: &ScalarVector<C>) -> Self {
    assert_eq!(self.len(), vector.len());
    let mut res = self.clone();
    for (i, val) in res.0.iter_mut().enumerate() {
      *val *= vector.0[i];
    }
    res
  }
  */

  #[cfg(test)]
  pub(crate) fn multiexp(&self, vector: &ScalarVector<C>) -> C::G {
    assert_eq!(self.len(), vector.len());
    let mut res = Vec::with_capacity(self.len());
    for (point, scalar) in self.0.iter().copied().zip(vector.0.iter().copied()) {
      res.push((scalar, point));
    }
    multiexp(&res)
  }

  /*
  pub(crate) fn multiexp_vartime(&self, vector: &ScalarVector<C>) -> C::G {
    assert_eq!(self.len(), vector.len());
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

  pub fn split(mut self) -> (Self, Self) {
    assert!(self.len() > 1);
    let r = self.0.split_off(self.0.len() / 2);
    assert_eq!(self.len(), r.len());
    (self, PointVector(r))
  }

  pub(crate) fn transcript<T: 'static + Transcript>(
    &self,
    transcript: &mut T,
    label: &'static [u8],
  ) {
    for point in &self.0 {
      transcript.append_message(label, point.to_bytes());
    }
  }
}
