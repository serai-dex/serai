use core::ops::{Index, IndexMut};
use std_shims::vec::Vec;

use zeroize::{Zeroize, ZeroizeOnDrop};

use curve25519_dalek::edwards::EdwardsPoint;

#[cfg(test)]
use crate::{core::multiexp, plus::ScalarVector};

#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct PointVector(pub(crate) Vec<EdwardsPoint>);

impl Index<usize> for PointVector {
  type Output = EdwardsPoint;
  fn index(&self, index: usize) -> &EdwardsPoint {
    &self.0[index]
  }
}

impl IndexMut<usize> for PointVector {
  fn index_mut(&mut self, index: usize) -> &mut EdwardsPoint {
    &mut self.0[index]
  }
}

impl PointVector {
  #[cfg(test)]
  pub(crate) fn multiexp(&self, vector: &ScalarVector) -> EdwardsPoint {
    debug_assert_eq!(self.len(), vector.len());
    let mut res = Vec::with_capacity(self.len());
    for (point, scalar) in self.0.iter().copied().zip(vector.0.iter().copied()) {
      res.push((scalar, point));
    }
    multiexp(&res)
  }

  pub(crate) fn len(&self) -> usize {
    self.0.len()
  }

  pub(crate) fn split(mut self) -> (Self, Self) {
    debug_assert!(self.len() > 1);
    let r = self.0.split_off(self.0.len() / 2);
    debug_assert_eq!(self.len(), r.len());
    (self, PointVector(r))
  }
}
