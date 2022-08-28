use core::{
  ops::{Add, AddAssign, Neg, Sub, SubAssign, Mul, MulAssign},
  iter::Sum,
};

use lazy_static::lazy_static;

use rand_core::RngCore;

use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable, ConditionallyNegatable};

use ff::{Field, PrimeField, PrimeFieldBits};
use group::{Group, GroupEncoding, prime::PrimeGroup};

use crate::{
  scalar::{Scalar, MODULUS as SCALAR_MODULUS},
  field::{FieldElement, Q_4},
};

lazy_static! {
  static ref D: FieldElement = -FieldElement::from(39081u16);
}

fn recover_x(y: FieldElement) -> CtOption<FieldElement> {
  let ysq = y.square();
  ((*D * ysq) - FieldElement::one()).invert().and_then(|inverted| {
    let temp = (ysq - FieldElement::one()) * inverted;
    let mut x = temp.pow(*Q_4);
    x.conditional_negate(x.is_odd());

    let xsq = x.square();
    CtOption::new(x, (xsq + ysq).ct_eq(&(FieldElement::one() + (*D * xsq * ysq))))
  })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Point {
  x: FieldElement,
  y: FieldElement,
}

lazy_static! {
  static ref G_Y: FieldElement = FieldElement::from_repr(
    hex_literal::hex!(
      "14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900"
    ).into()
  ).unwrap();
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
    // Precompute the optimal amount that's a multiple of 2
    let mut table = [Point::identity(); 16];
    table[1] = self;
    for i in 2 .. 16 {
      table[i] = table[i - 1] + self;
    }

    let mut res = Self::identity();
    let mut bits = 0;
    for (i, bit) in other.to_le_bits().iter().rev().enumerate() {
      bits <<= 1;
      let bit = *bit as u8;
      assert_eq!(bit | 1, 1);
      bits |= bit;

      if ((i + 1) % 4) == 0 {
        if i != 3 {
          for _ in 0 .. 4 {
            res += res;
          }
        }
        res += table[usize::from(bits)];
        bits = 0;
      }
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
    (*self * *SCALAR_MODULUS).is_identity()
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
        x.conditional_negate(x.is_odd().ct_eq(&!Choice::from(sign)));
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
    mut_ref[56] |= self.x.is_odd().unwrap_u8() << 7;
    bytes
  }
}

impl PrimeGroup for Point {}

#[test]
fn identity() {
  assert_eq!(Point::from_bytes(&Point::identity().to_bytes()).unwrap(), Point::identity());
  assert_eq!(Point::identity() + Point::identity(), Point::identity());
}

#[test]
fn addition_multiplication_serialization() {
  let mut accum = Point::identity();
  for x in 1 .. 10 {
    accum += Point::generator();
    let mul = Point::generator() * Scalar::from(x as u8);
    assert_eq!(accum, mul);
    assert_eq!(Point::from_bytes(&mul.to_bytes()).unwrap(), mul);
  }
}

#[test]
fn torsion() {
  // Uses the originally suggested generator which had torsion
  let old_y = FieldElement::from_repr(
    hex_literal::hex!(
      "12796c1532041525945f322e414d434467cfd5c57c9a9af2473b27758c921c4828b277ca5f2891fc4f3d79afdf29a64c72fb28b59c16fa5100"
    ).into()
  ).unwrap();
  let old = Point { x: -recover_x(old_y).unwrap(), y: old_y };
  assert!(bool::from(!old.is_torsion_free()));
}

#[test]
fn vector() {
  use generic_array::GenericArray;

  assert_eq!(
    Point::generator().double(),
    Point::from_bytes(
      GenericArray::from_slice(
        &hex::decode("\
ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a\
726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae\
80"
        ).unwrap()
      )
    ).unwrap()
  );

  assert_eq!(
    Point::generator() * Scalar::from_repr(
      *GenericArray::from_slice(
        &hex::decode("\
6298e1eef3c379392caaed061ed8a31033c9e9e3420726f23b404158\
a401cd9df24632adfe6b418dc942d8a091817dd8bd70e1c72ba52f3c\
00"
        ).unwrap()
      )
    ).unwrap(),
    Point::from_bytes(
      GenericArray::from_slice(
        &hex::decode("\
3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba2\
65632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b0\
00"
        ).unwrap()
      )
    ).unwrap()
  );
}
