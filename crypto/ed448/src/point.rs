use core::{
  ops::{Add, AddAssign, Neg, Sub, SubAssign, Mul, MulAssign},
  iter::Sum,
};

use lazy_static::lazy_static;

use rand_core::RngCore;

use zeroize::Zeroize;
use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable, ConditionallyNegatable};

use crypto_bigint::U512;

use ff::{Field, PrimeField, PrimeFieldBits};
use group::{Group, GroupEncoding, prime::PrimeGroup};

use crate::{
  scalar::{Scalar, MODULUS as SCALAR_MODULUS},
  field::{FieldElement, MODULUS as FIELD_MODULUS, Q_4},
};

const D: FieldElement = FieldElement(FIELD_MODULUS.0.saturating_sub(&U512::from_u16(39081)));

const G_Y: FieldElement = FieldElement(U512::from_be_hex(concat!(
  "00000000000000",
  "00",
  "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e",
  "05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14",
)));

fn recover_x(y: FieldElement) -> CtOption<FieldElement> {
  let ysq = y.square();
  #[allow(non_snake_case)]
  let D_ysq = D * ysq;
  (D_ysq - FieldElement::one()).invert().and_then(|inverted| {
    let temp = (ysq - FieldElement::one()) * inverted;
    let mut x = temp.pow(Q_4);
    x.conditional_negate(x.is_odd());

    let xsq = x.square();
    CtOption::new(x, (xsq + ysq).ct_eq(&(FieldElement::one() + (xsq * D_ysq))))
  })
}

#[derive(Clone, Copy, Debug, Zeroize)]
pub struct Point {
  x: FieldElement,
  y: FieldElement,
  z: FieldElement,
}

lazy_static! {
  static ref G: Point = Point { x: recover_x(G_Y).unwrap(), y: G_Y, z: FieldElement::one() };
}

impl ConstantTimeEq for Point {
  fn ct_eq(&self, other: &Self) -> Choice {
    let x1 = self.x * other.z;
    let x2 = other.x * self.z;

    let y1 = self.y * other.z;
    let y2 = other.y * self.z;

    x1.ct_eq(&x2) & y1.ct_eq(&y2)
  }
}

impl PartialEq for Point {
  fn eq(&self, other: &Point) -> bool {
    self.ct_eq(other).into()
  }
}

impl Eq for Point {}

impl ConditionallySelectable for Point {
  fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
    Point {
      x: FieldElement::conditional_select(&a.x, &b.x, choice),
      y: FieldElement::conditional_select(&a.y, &b.y, choice),
      z: FieldElement::conditional_select(&a.z, &b.z, choice),
    }
  }
}

impl Add for Point {
  type Output = Point;
  fn add(self, other: Self) -> Self {
    // 12 muls, 7 additions, 4 negations
    let xcp = self.x * other.x;
    let ycp = self.y * other.y;
    let zcp = self.z * other.z;
    #[allow(non_snake_case)]
    let B = zcp.square();
    #[allow(non_snake_case)]
    let E = D * xcp * ycp;
    #[allow(non_snake_case)]
    let F = B - E;
    #[allow(non_snake_case)]
    let G_ = B + E;

    Point {
      x: zcp * F * ((self.x + self.y) * (other.x + other.y) - xcp - ycp),
      y: zcp * G_ * (ycp - xcp),
      z: F * G_,
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
    Point { x: -self.x, y: self.y, z: self.z }
  }
}

impl Sub for Point {
  type Output = Point;
  #[allow(clippy::suspicious_arithmetic_impl)]
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
  fn random(mut rng: impl RngCore) -> Self {
    loop {
      let mut bytes = FieldElement::random(&mut rng).to_repr();
      let mut_ref: &mut [u8] = bytes.as_mut();
      mut_ref[56] |= u8::try_from(rng.next_u32() % 2).unwrap() << 7;
      let opt = Self::from_bytes(&bytes);
      if opt.is_some().into() {
        return opt.unwrap();
      }
    }
  }
  fn identity() -> Self {
    Point { x: FieldElement::zero(), y: FieldElement::one(), z: FieldElement::one() }
  }
  fn generator() -> Self {
    *G
  }
  fn is_identity(&self) -> Choice {
    self.ct_eq(&Self::identity())
  }
  fn double(&self) -> Self {
    // 7 muls, 7 additions, 4 negations
    let xsq = self.x.square();
    let ysq = self.y.square();
    let zsq = self.z.square();
    let xy = self.x + self.y;
    #[allow(non_snake_case)]
    let F = xsq + ysq;
    #[allow(non_snake_case)]
    let J = F - zsq.double();
    Point { x: J * (xy.square() - xsq - ysq), y: F * (xsq - ysq), z: F * J }
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
      let bit = u8::from(*bit);
      bits |= bit;

      if ((i + 1) % 4) == 0 {
        if i != 3 {
          for _ in 0 .. 4 {
            res = res.double();
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
  pub fn is_torsion_free(&self) -> Choice {
    (*self * SCALAR_MODULUS).is_identity()
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
        x.conditional_negate(x.is_odd().ct_eq(&!sign));
        let not_negative_zero = !(x.is_zero() & sign);
        let point = Point { x, y, z: FieldElement::one() };
        CtOption::new(point, not_negative_zero & point.is_torsion_free())
      })
    })
  }

  fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
    Point::from_bytes(bytes)
  }

  fn to_bytes(&self) -> Self::Repr {
    let z = self.z.invert().unwrap();
    let x = self.x * z;
    let y = self.y * z;

    let mut bytes = y.to_repr();
    let mut_ref: &mut [u8] = bytes.as_mut();
    mut_ref[56] |= x.is_odd().unwrap_u8() << 7;
    bytes
  }
}

impl PrimeGroup for Point {}

#[test]
fn test_group() {
  // TODO: Move to test_prime_group_bits once the impl is finished
  use ff_group_tests::group::*;

  test_eq::<Point>();
  test_identity::<Point>();
  test_generator::<Point>();
  test_double::<Point>();
  test_add::<Point>();
  test_sum::<Point>();
  test_neg::<Point>();
  test_sub::<Point>();
  test_mul::<Point>();
  test_order::<Point>();
  test_random::<_, Point>(&mut rand_core::OsRng);

  test_encoding::<Point>();
}

#[test]
fn torsion() {
  use generic_array::GenericArray;

  // Uses the originally suggested generator which had torsion
  let old_y = FieldElement::from_repr(*GenericArray::from_slice(
    &hex::decode(
      "\
12796c1532041525945f322e414d434467cfd5c57c9a9af2473b2775\
8c921c4828b277ca5f2891fc4f3d79afdf29a64c72fb28b59c16fa51\
00",
    )
    .unwrap(),
  ))
  .unwrap();
  let old = Point { x: -recover_x(old_y).unwrap(), y: old_y, z: FieldElement::one() };
  assert!(bool::from(!old.is_torsion_free()));
}

#[test]
fn vector() {
  use generic_array::GenericArray;

  assert_eq!(
    Point::generator().double(),
    Point::from_bytes(GenericArray::from_slice(
      &hex::decode(
        "\
ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a\
726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae\
80"
      )
      .unwrap()
    ))
    .unwrap()
  );

  assert_eq!(
    Point::generator() *
      Scalar::from_repr(*GenericArray::from_slice(
        &hex::decode(
          "\
6298e1eef3c379392caaed061ed8a31033c9e9e3420726f23b404158\
a401cd9df24632adfe6b418dc942d8a091817dd8bd70e1c72ba52f3c\
00"
        )
        .unwrap()
      ))
      .unwrap(),
    Point::from_bytes(GenericArray::from_slice(
      &hex::decode(
        "\
3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba2\
65632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b0\
00"
      )
      .unwrap()
    ))
    .unwrap()
  );
}

// Checks random won't infinitely loop
#[test]
fn random() {
  Point::random(&mut rand_core::OsRng);
}
