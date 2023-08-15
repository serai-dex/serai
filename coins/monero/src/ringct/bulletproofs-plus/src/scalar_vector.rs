use core::{
  borrow::Borrow,
  ops::{Index, IndexMut},
};

use zeroize::Zeroize;

use transcript::Transcript;

use ciphersuite::{
  group::ff::{Field, PrimeField},
  Ciphersuite,
};

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct ScalarVector<C: Ciphersuite>(pub Vec<C::F>);

impl<C: Ciphersuite> Index<usize> for ScalarVector<C> {
  type Output = C::F;
  fn index(&self, index: usize) -> &C::F {
    &self.0[index]
  }
}

impl<C: Ciphersuite> IndexMut<usize> for ScalarVector<C> {
  fn index_mut(&mut self, index: usize) -> &mut C::F {
    &mut self.0[index]
  }
}

impl<C: Ciphersuite> ScalarVector<C> {
  pub(crate) fn new(len: usize) -> Self {
    ScalarVector(vec![C::F::ZERO; len])
  }

  pub(crate) fn add(&self, scalar: impl Borrow<C::F>) -> Self {
    let mut res = self.clone();
    for val in res.0.iter_mut() {
      *val += scalar.borrow();
    }
    res
  }

  pub(crate) fn sub(&self, scalar: impl Borrow<C::F>) -> Self {
    let mut res = self.clone();
    for val in res.0.iter_mut() {
      *val -= scalar.borrow();
    }
    res
  }

  pub(crate) fn mul(&self, scalar: impl Borrow<C::F>) -> Self {
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

  /*
  pub(crate) fn sub_vec(&self, vector: &Self) -> Self {
    assert_eq!(self.len(), vector.len());
    let mut res = self.clone();
    for (i, val) in res.0.iter_mut().enumerate() {
      *val -= vector.0[i];
    }
    res
  }
  */

  pub(crate) fn mul_vec(&self, vector: &Self) -> Self {
    assert_eq!(self.len(), vector.len());
    let mut res = self.clone();
    for (i, val) in res.0.iter_mut().enumerate() {
      *val *= vector.0[i];
    }
    res
  }

  pub(crate) fn inner_product(&self, vector: &Self) -> C::F {
    self.mul_vec(vector).sum()
  }

  pub(crate) fn powers(x: C::F, len: usize) -> Self {
    debug_assert!(len != 0);

    let mut res = Vec::with_capacity(len);
    res.push(C::F::ONE);
    res.push(x);
    for i in 2 .. len {
      res.push(res[i - 1] * x);
    }
    res.truncate(len);
    ScalarVector(res)
  }

  pub(crate) fn sum(mut self) -> C::F {
    self.0.drain(..).sum()
  }

  pub(crate) fn len(&self) -> usize {
    self.0.len()
  }

  pub fn split(mut self) -> (Self, Self) {
    assert!(self.len() > 1);
    let r = self.0.split_off(self.0.len() / 2);
    assert_eq!(self.len(), r.len());
    (self, ScalarVector(r))
  }

  pub fn transcript<T: 'static + Transcript>(&self, transcript: &mut T, label: &'static [u8]) {
    for scalar in &self.0 {
      transcript.append_message(label, scalar.to_repr());
    }
  }
}

pub fn weighted_inner_product<C: Ciphersuite>(
  a: &ScalarVector<C>,
  b: &ScalarVector<C>,
  y: &ScalarVector<C>,
) -> C::F {
  a.inner_product(&b.mul_vec(y))
}
