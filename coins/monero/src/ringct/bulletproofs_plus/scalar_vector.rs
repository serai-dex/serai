use core::{
  borrow::Borrow,
  ops::{Index, IndexMut},
};

use zeroize::Zeroize;

use transcript::Transcript;

use group::ff::{Field, PrimeField};
use dalek_ff_group::Scalar;

#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub(crate) struct ScalarVector(pub(crate) Vec<Scalar>);

impl Index<usize> for ScalarVector {
  type Output = Scalar;
  fn index(&self, index: usize) -> &Scalar {
    &self.0[index]
  }
}

impl IndexMut<usize> for ScalarVector {
  fn index_mut(&mut self, index: usize) -> &mut Scalar {
    &mut self.0[index]
  }
}

impl ScalarVector {
  pub(crate) fn new(len: usize) -> Self {
    ScalarVector(vec![Scalar::ZERO; len])
  }

  pub(crate) fn add(&self, scalar: impl Borrow<Scalar>) -> Self {
    let mut res = self.clone();
    for val in res.0.iter_mut() {
      *val += scalar.borrow();
    }
    res
  }

  pub(crate) fn sub(&self, scalar: impl Borrow<Scalar>) -> Self {
    let mut res = self.clone();
    for val in res.0.iter_mut() {
      *val -= scalar.borrow();
    }
    res
  }

  pub(crate) fn mul(&self, scalar: impl Borrow<Scalar>) -> Self {
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

  pub(crate) fn mul_vec(&self, vector: &Self) -> Self {
    assert_eq!(self.len(), vector.len());
    let mut res = self.clone();
    for (i, val) in res.0.iter_mut().enumerate() {
      *val *= vector.0[i];
    }
    res
  }

  pub(crate) fn inner_product(&self, vector: &Self) -> Scalar {
    self.mul_vec(vector).sum()
  }

  pub(crate) fn powers(x: Scalar, len: usize) -> Self {
    debug_assert!(len != 0);

    let mut res = Vec::with_capacity(len);
    res.push(Scalar::ONE);
    res.push(x);
    for i in 2 .. len {
      res.push(res[i - 1] * x);
    }
    res.truncate(len);
    ScalarVector(res)
  }

  pub(crate) fn sum(mut self) -> Scalar {
    self.0.drain(..).sum()
  }

  pub(crate) fn len(&self) -> usize {
    self.0.len()
  }

  pub(crate) fn split(mut self) -> (Self, Self) {
    assert!(self.len() > 1);
    let r = self.0.split_off(self.0.len() / 2);
    assert_eq!(self.len(), r.len());
    (self, ScalarVector(r))
  }

  pub(crate) fn transcript<T: 'static + Transcript>(
    &self,
    transcript: &mut T,
    label: &'static [u8],
  ) {
    for scalar in &self.0 {
      transcript.append_message(label, scalar.to_repr());
    }
  }
}

pub(crate) fn weighted_inner_product(
  a: &ScalarVector,
  b: &ScalarVector,
  y: &ScalarVector,
) -> Scalar {
  a.inner_product(&b.mul_vec(y))
}
