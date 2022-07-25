use core::{ops::{Add, Sub, Mul, Index}, slice::SliceIndex};

use lazy_static::lazy_static;

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
  }
}
math_op!(Add, add, |(a, b): (&Scalar, &Scalar)| *a + *b);
math_op!(Sub, sub, |(a, b): (&Scalar, &Scalar)| *a - *b);
math_op!(Mul, mul, |(a, b): (&Scalar, &Scalar)| *a * *b);

impl Mul<&[EdwardsPoint]> for &ScalarVector {
  type Output = EdwardsPoint;
  fn mul(self, b: &[EdwardsPoint]) -> EdwardsPoint {
    assert_eq!(self.len(), b.len());
    multiexp(&self.0.iter().cloned().zip(b.iter().cloned()).collect::<Vec<_>>())
  }
}

impl ScalarVector {
  pub(crate) fn len(&self) -> usize {
    self.0.len()
  }

  pub(crate) fn slice<Idx: SliceIndex<[Scalar], Output = [Scalar]>>(&self, index: Idx) -> ScalarVector {
    ScalarVector((&self.0[index]).to_vec())
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

pub(crate) fn vector_powers(x: Scalar, n: usize) -> ScalarVector {
  let mut res = Vec::with_capacity(n);
  if n == 0 {
    return ScalarVector(res);
  }

  res.push(Scalar::one());
  for i in 1 .. n {
    res.push(res[i - 1] * x);
  }

  ScalarVector(res)
}

pub(crate) fn hadamard_fold(v: &mut Vec<EdwardsPoint>, a: Scalar, b: Scalar, scale: Option<&ScalarVector>) {
  let half = v.len() / 2;
  assert_eq!(half * 2, v.len());

  for n in 0 .. half {
    v[n] = multiexp(&[
      (a * scale.map(|s| s[n]).unwrap_or_else(Scalar::one), v[n]),
      (b * scale.map(|s| s[half + n]).unwrap_or_else(Scalar::one), v[half + n])
    ]);
  }

  v.truncate(half);
}
