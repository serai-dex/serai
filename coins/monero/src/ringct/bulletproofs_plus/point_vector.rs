use core::ops::{Index, IndexMut};

use zeroize::{Zeroize, ZeroizeOnDrop};

use dalek_ff_group::EdwardsPoint;

#[cfg(test)]
use multiexp::multiexp;
#[cfg(test)]
use crate::ringct::bulletproofs_plus::ScalarVector;

#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PointVector(pub Vec<EdwardsPoint>);

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
    assert_eq!(self.len(), vector.len());
    let mut res = Vec::with_capacity(self.len());
    for (point, scalar) in self.0.iter().copied().zip(vector.0.iter().copied()) {
      res.push((scalar, point));
    }
    multiexp(&res)
  }

  pub(crate) fn len(&self) -> usize {
    self.0.len()
  }

  pub fn split(mut self) -> (Self, Self) {
    assert!(self.len() > 1);
    let r = self.0.split_off(self.0.len() / 2);
    assert_eq!(self.len(), r.len());
    (self, PointVector(r))
  }
}
