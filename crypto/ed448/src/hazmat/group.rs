use core::{
  ops::{Add, AddAssign, Neg, Sub, SubAssign, Mul, MulAssign, Div},
  iter::Sum,
};

use lazy_static::lazy_static;

use rand_core::RngCore;

use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable, ConditionallyNegatable};

use crypto_bigint::{NonZero, U512};

use ff::{Field, PrimeField, PrimeFieldBits};
use group::{Group, GroupEncoding, prime::PrimeGroup};

use crate::{
  choice,
  scalar::{Scalar, MODULUS as SCALAR_MODULUS},
  field::{FieldElement, MODULUS as FIELD_MODULUS},
};

lazy_static! {
  static ref Q_4: FieldElement = FieldElement(
    (FIELD_MODULUS.saturating_add(&U512::from(1u8))).div(NonZero::new(U512::from(4u8)).unwrap())
  );
  static ref D: FieldElement = -FieldElement::from(39081u16);
}

fn recover_x(y: FieldElement) -> CtOption<FieldElement> {
  let ysq = y.square();
  ((*D * ysq) - FieldElement::one()).invert().and_then(|inverted| {
    let temp = (ysq - FieldElement::one()) * inverted;
    let mut x = temp.pow(*Q_4);
    x.conditional_negate(x.is_odd());

    let xsq = x.square();
    let ysq = y.square();
    CtOption::new(x, (xsq + ysq - FieldElement::one() - (*D * xsq * ysq)).is_zero())
  })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Point {
  x: FieldElement,
  y: FieldElement,
}

lazy_static! {
  static ref G_Y: FieldElement = FieldElement(U512::from_be_hex(
    "0000000000000000\
693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e\
05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14"
  ));
  static ref G: Point = Point { x: recover_x(*G_Y).unwrap(), y: *G_Y };
}

impl ConstantTimeEq for Point {
  fn ct_eq(&self, other: &Self) -> Choice {
    self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
  }
}

impl ConditionallySelectable for Point {
  fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
    Point {
      x: FieldElement::conditional_select(&a.x, &b.x, choice),
      y: FieldElement::conditional_select(&a.y, &b.y, choice),
    }
  }
}

impl Add for Point {
  type Output = Point;
  fn add(self, other: Self) -> Self {
    let y3 = self.y * other.y;
    let x3 = self.x * other.x;
    let dxy3 = *D * x3 * y3;
    Point {
      x: ((self.x * other.y) + (other.x * self.y)) *
        (FieldElement::one() + dxy3).invert().unwrap_or(FieldElement::zero()),
      y: (y3 - x3) * (FieldElement::one() - dxy3).invert().unwrap_or(FieldElement::zero()),
    }
  }
}

impl AddAssign for Point {
  fn add_assign(&mut self, other: Point) {
    *self = *self + other;
  }
}

impl Add<&Point> for Point {
  type Output = Point;
  fn add(self, other: &Point) -> Point {
    self + *other
  }
}

impl AddAssign<&Point> for Point {
  fn add_assign(&mut self, other: &Point) {
    *self += *other;
  }
}

impl Neg for Point {
  type Output = Point;
  fn neg(self) -> Self {
    Point { x: -self.x, y: self.y }
  }
}

impl Sub for Point {
  type Output = Point;
  fn sub(self, other: Self) -> Self {
    self + other.neg()
  }
}

impl SubAssign for Point {
  fn sub_assign(&mut self, other: Point) {
    *self = *self - other;
  }
}

impl Sub<&Point> for Point {
  type Output = Point;
  fn sub(self, other: &Point) -> Point {
    self - *other
  }
}

impl SubAssign<&Point> for Point {
  fn sub_assign(&mut self, other: &Point) {
    *self -= *other;
  }
}

impl Group for Point {
  type Scalar = Scalar;
  // Ideally, this would be cryptographically secure, yet that's not a bound on the trait
  // k256 also does this
  fn random(rng: impl RngCore) -> Self {
    Self::generator() * Scalar::random(rng)
  }
  fn identity() -> Self {
    Point { x: FieldElement::zero(), y: FieldElement::one() }
  }
  fn generator() -> Self {
    *G
  }
  fn is_identity(&self) -> Choice {
    self.ct_eq(&Self::identity())
  }
  fn double(&self) -> Self {
    *self + self
  }
}

impl Sum<Point> for Point {
  fn sum<I: Iterator<Item = Point>>(iter: I) -> Point {
    let mut res = Self::identity();
    for i in iter {
      res += i;
    }
    res
  }
}

impl<'a> Sum<&'a Point> for Point {
  fn sum<I: Iterator<Item = &'a Point>>(iter: I) -> Point {
    Point::sum(iter.cloned())
  }
}

impl Mul<Scalar> for Point {
  type Output = Point;
  fn mul(self, other: Scalar) -> Point {
    let mut res = Self::identity();
    for bit in other.to_le_bits().iter().rev() {
      res += res;
      res += Self::conditional_select(&Self::identity(), &Self::generator(), choice(*bit));
    }
    res
  }
}

impl MulAssign<Scalar> for Point {
  fn mul_assign(&mut self, other: Scalar) {
    *self = *self * other;
  }
}

impl Mul<&Scalar> for Point {
  type Output = Point;
  fn mul(self, other: &Scalar) -> Point {
    self * *other
  }
}

impl MulAssign<&Scalar> for Point {
  fn mul_assign(&mut self, other: &Scalar) {
    *self *= *other;
  }
}

impl Point {
  fn is_torsion_free(&self) -> Choice {
    (*self * Scalar(*SCALAR_MODULUS)).is_identity()
  }
}

impl GroupEncoding for Point {
  type Repr = <FieldElement as PrimeField>::Repr;

  fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
    // Extract and clear the sign bit
    let sign = Choice::from(bytes[56] >> 7);
    let mut bytes = *bytes;
    let mut_ref: &mut [u8] = bytes.as_mut();
    mut_ref[56] &= !(1 << 7);

    // Parse y, recover x
    FieldElement::from_repr(bytes).and_then(|y| {
      recover_x(y).and_then(|mut x| {
        x.conditional_negate(x.is_odd().ct_eq(&Choice::from(sign)));
        let not_negative_zero = !(x.is_zero() & sign);
        let point = Point { x, y };
        CtOption::new(point, not_negative_zero & point.is_torsion_free())
      })
    })
  }

  fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
    Point::from_bytes(bytes)
  }

  fn to_bytes(&self) -> Self::Repr {
    let mut bytes = self.y.to_repr();
    let mut_ref: &mut [u8] = bytes.as_mut();
    mut_ref[56] |= self.x.is_odd().unwrap_u8();
    bytes
  }
}

impl PrimeGroup for Point {}
