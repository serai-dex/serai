use core::{
  borrow::Borrow,
  ops::{Index, IndexMut, Add, Sub, Mul},
};
use std_shims::{vec, vec::Vec};

use zeroize::{Zeroize, ZeroizeOnDrop};

use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint};

use crate::core::multiexp;

#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
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

impl<S: Borrow<Scalar>> Add<S> for ScalarVector {
  type Output = ScalarVector;
  fn add(mut self, scalar: S) -> ScalarVector {
    for s in &mut self.0 {
      *s += scalar.borrow();
    }
    self
  }
}
impl<S: Borrow<Scalar>> Sub<S> for ScalarVector {
  type Output = ScalarVector;
  fn sub(mut self, scalar: S) -> ScalarVector {
    for s in &mut self.0 {
      *s -= scalar.borrow();
    }
    self
  }
}
impl<S: Borrow<Scalar>> Mul<S> for ScalarVector {
  type Output = ScalarVector;
  fn mul(mut self, scalar: S) -> ScalarVector {
    for s in &mut self.0 {
      *s *= scalar.borrow();
    }
    self
  }
}

impl Add<&ScalarVector> for ScalarVector {
  type Output = ScalarVector;
  fn add(mut self, other: &ScalarVector) -> ScalarVector {
    debug_assert_eq!(self.len(), other.len());
    for (s, o) in self.0.iter_mut().zip(other.0.iter()) {
      *s += o;
    }
    self
  }
}
impl Sub<&ScalarVector> for ScalarVector {
  type Output = ScalarVector;
  fn sub(mut self, other: &ScalarVector) -> ScalarVector {
    debug_assert_eq!(self.len(), other.len());
    for (s, o) in self.0.iter_mut().zip(other.0.iter()) {
      *s -= o;
    }
    self
  }
}
impl Mul<&ScalarVector> for ScalarVector {
  type Output = ScalarVector;
  fn mul(mut self, other: &ScalarVector) -> ScalarVector {
    debug_assert_eq!(self.len(), other.len());
    for (s, o) in self.0.iter_mut().zip(other.0.iter()) {
      *s *= o;
    }
    self
  }
}

impl Mul<&[EdwardsPoint]> for &ScalarVector {
  type Output = EdwardsPoint;
  fn mul(self, b: &[EdwardsPoint]) -> EdwardsPoint {
    debug_assert_eq!(self.len(), b.len());
    let mut multiexp_args = self.0.iter().copied().zip(b.iter().copied()).collect::<Vec<_>>();
    let res = multiexp(&multiexp_args);
    multiexp_args.zeroize();
    res
  }
}

impl ScalarVector {
  pub(crate) fn new(len: usize) -> Self {
    ScalarVector(vec![Scalar::ZERO; len])
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

  pub(crate) fn len(&self) -> usize {
    self.0.len()
  }

  pub(crate) fn sum(mut self) -> Scalar {
    self.0.drain(..).sum()
  }

  pub(crate) fn inner_product(self, vector: &Self) -> Scalar {
    (self * vector).sum()
  }

  pub(crate) fn weighted_inner_product(self, vector: &Self, y: &Self) -> Scalar {
    (self * vector * y).sum()
  }

  pub(crate) fn split(mut self) -> (Self, Self) {
    debug_assert!(self.len() > 1);
    let r = self.0.split_off(self.0.len() / 2);
    debug_assert_eq!(self.len(), r.len());
    (self, ScalarVector(r))
  }
}
