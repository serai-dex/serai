use core::ops::{Add, Sub, Mul, Index};

use group::ff::Field;
use dalek_ff_group::{Scalar, EdwardsPoint};

use multiexp::multiexp;

#[derive(Clone, PartialEq, Eq, Debug)]
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
        assert_eq!(self.len(), b.len());
        ScalarVector(self.0.iter().zip(b.0.iter()).map($f).collect())
      }
    }

    impl $Op<&ScalarVector> for &ScalarVector {
      type Output = ScalarVector;
      fn $op(self, b: &ScalarVector) -> ScalarVector {
        assert_eq!(self.len(), b.len());
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
    let mut res = Vec::with_capacity(len);
    if len == 0 {
      return ScalarVector(res);
    }

    res.push(Scalar::one());
    for i in 1 .. len {
      res.push(res[i - 1] * x);
    }

    ScalarVector(res)
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
  (a * b).0.drain(..).sum()
}

impl Mul<&[EdwardsPoint]> for &ScalarVector {
  type Output = EdwardsPoint;
  fn mul(self, b: &[EdwardsPoint]) -> EdwardsPoint {
    assert_eq!(self.len(), b.len());
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
