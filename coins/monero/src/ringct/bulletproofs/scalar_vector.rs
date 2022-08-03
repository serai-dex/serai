use core::ops::{Add, Sub, Mul, Index};

use zeroize::{Zeroize, ZeroizeOnDrop};

use group::ff::Field;
use dalek_ff_group::{Scalar, EdwardsPoint};

use multiexp::multiexp;

#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub(crate) struct ScalarVector(pub(crate) Vec<Scalar>);
macro_rules! math_op {
  ($Op: ident, $op: ident, $f: expr) => {
    impl $Op<Scalar> for ScalarVector {
      type Output = ScalarVector;
      fn $op(self, b: Scalar) -> ScalarVector {
        ScalarVector(self.0.iter().map(|a| $f((a, &b))).collect())
      }
    }

    impl $Op<Scalar> for &ScalarVector {
      type Output = ScalarVector;
      fn $op(self, b: Scalar) -> ScalarVector {
        ScalarVector(self.0.iter().map(|a| $f((a, &b))).collect())
      }
    }

    impl $Op<ScalarVector> for ScalarVector {
      type Output = ScalarVector;
      fn $op(self, b: ScalarVector) -> ScalarVector {
        debug_assert_eq!(self.len(), b.len());
        ScalarVector(self.0.iter().zip(b.0.iter()).map($f).collect())
      }
    }

    impl $Op<&ScalarVector> for &ScalarVector {
      type Output = ScalarVector;
      fn $op(self, b: &ScalarVector) -> ScalarVector {
        debug_assert_eq!(self.len(), b.len());
        ScalarVector(self.0.iter().zip(b.0.iter()).map($f).collect())
      }
    }
  };
}
math_op!(Add, add, |(a, b): (&Scalar, &Scalar)| *a + *b);
math_op!(Sub, sub, |(a, b): (&Scalar, &Scalar)| *a - *b);
math_op!(Mul, mul, |(a, b): (&Scalar, &Scalar)| *a * *b);

impl ScalarVector {
  pub(crate) fn new(len: usize) -> ScalarVector {
    ScalarVector(vec![Scalar::zero(); len])
  }

  pub(crate) fn powers(x: Scalar, len: usize) -> ScalarVector {
    debug_assert!(len != 0);

    let mut res = Vec::with_capacity(len);
    res.push(Scalar::one());
    for i in 1 .. len {
      res.push(res[i - 1] * x);
    }
    ScalarVector(res)
  }

  pub(crate) fn even_powers(x: Scalar, pow: usize) -> ScalarVector {
    debug_assert!(pow != 0);
    // Verify pow is a power of two
    debug_assert_eq!(((pow - 1) & pow), 0);

    let xsq = x * x;
    let mut res = ScalarVector(Vec::with_capacity(pow / 2));
    res.0.push(xsq);

    let mut prev = 2;
    while prev < pow {
      res.0.push(res[res.len() - 1] * xsq);
      prev += 2;
    }

    res
  }

  pub(crate) fn sum(mut self) -> Scalar {
    self.0.drain(..).sum()
  }

  pub(crate) fn len(&self) -> usize {
    self.0.len()
  }

  pub(crate) fn split(self) -> (ScalarVector, ScalarVector) {
    let (l, r) = self.0.split_at(self.0.len() / 2);
    (ScalarVector(l.to_vec()), ScalarVector(r.to_vec()))
  }
}

impl Index<usize> for ScalarVector {
  type Output = Scalar;
  fn index(&self, index: usize) -> &Scalar {
    &self.0[index]
  }
}

pub(crate) fn inner_product(a: &ScalarVector, b: &ScalarVector) -> Scalar {
  (a * b).sum()
}

pub(crate) fn weighted_powers(x: Scalar, len: usize) -> ScalarVector {
  ScalarVector(ScalarVector::powers(x, len + 1).0[1 ..].to_vec())
}

pub(crate) fn weighted_inner_product(a: &ScalarVector, b: &ScalarVector, y: Scalar) -> Scalar {
  // y ** 0 is not used as a power
  (a * b * weighted_powers(y, a.len())).sum()
}

impl Mul<&[EdwardsPoint]> for &ScalarVector {
  type Output = EdwardsPoint;
  fn mul(self, b: &[EdwardsPoint]) -> EdwardsPoint {
    debug_assert_eq!(self.len(), b.len());
    multiexp(&self.0.iter().cloned().zip(b.iter().cloned()).collect::<Vec<_>>())
  }
}

pub(crate) fn hadamard_fold(
  l: &[EdwardsPoint],
  r: &[EdwardsPoint],
  a: Scalar,
  b: Scalar,
) -> Vec<EdwardsPoint> {
  let mut res = Vec::with_capacity(l.len() / 2);
  for i in 0 .. l.len() {
    res.push(multiexp(&[(a, l[i]), (b, r[i])]));
  }
  res
}
