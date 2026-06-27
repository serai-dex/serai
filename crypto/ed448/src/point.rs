use core::{
  ops::{Add, AddAssign, Neg, Sub, SubAssign, Mul, MulAssign},
  iter::Sum,
};

use prime_field::{
  subtle::{
    Choice, CtOption, ConstantTimeEq, ConditionallySelectable, ConditionallyNegatable as _,
  },
  zeroize::Zeroize,
  rand_core::RngCore,
};
use crypto_bigint::U512;

use ciphersuite::group::{
  ff::{Field as _, PrimeField, PrimeFieldBits as _},
  Group, GroupEncoding,
  prime::PrimeGroup,
};

use crate::{u8_from_bool, Scalar, FieldElement};

const G_Y: FieldElement = {
  let bytes = U512::from_be_hex(concat!(
    "0000000000000000",
    "693f46716eb6bc248876203756c9c7624bea73736ca3984087789c1e",
    "05a0c2d73ad3ff1ce67c39c4fdbd132c4ed7c8ad9808795bf230fa14",
  ))
  .to_le_bytes();
  let mut dest = [0; 57];
  let mut i = 0;
  while i < dest.len() {
    dest[i] = bytes.as_slice()[i];
    i += 1;
  }
  FieldElement::from_bytes(&dest).unwrap()
};

const G_X: FieldElement = {
  let bytes = U512::from_be_hex(concat!(
    "0000000000000000",
    "4f1970c66bed0ded221d15a622bf36da9e146570470f1767ea6de324",
    "a3d3a46412ae1af72ab66511433b80e18b00938e2626a82bc70cc05e",
  ))
  .to_le_bytes();
  let mut dest = [0; 57];
  let mut i = 0;
  while i < dest.len() {
    dest[i] = bytes.as_slice()[i];
    i += 1;
  }
  FieldElement::from_bytes(&dest).unwrap()
};

fn recover_x(y: FieldElement) -> CtOption<FieldElement> {
  #[expect(non_snake_case)]
  let D = -<FieldElement as From<u16>>::from(39081u16);

  let ysq = y.square();
  #[expect(non_snake_case)]
  let D_ysq = D * ysq;
  (D_ysq - FieldElement::ONE).invert().and_then(|inverted| {
    let xsq = (ysq - FieldElement::ONE) * inverted;
    xsq.sqrt().and_then(|mut x| {
      x.conditional_negate(x.is_odd());
      CtOption::new(x, (xsq + ysq).ct_eq(&(FieldElement::ONE + (xsq * D_ysq))))
    })
  })
}

/// Ed448 point.
#[derive(Clone, Copy, Debug)]
pub struct Point {
  x: FieldElement,
  y: FieldElement,
  z: FieldElement,
}

impl Zeroize for Point {
  fn zeroize(&mut self) {
    self.x.zeroize();
    self.y.zeroize();
    self.z.zeroize();
    let identity = Self::identity();
    self.x = identity.x;
    self.y = identity.y;
    self.z = identity.z;
  }
}

const G: Point = Point { x: G_X, y: G_Y, z: FieldElement::ONE };

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
    #[expect(non_snake_case)]
    let D = -<FieldElement as From<u16>>::from(39081u16);

    // 12 muls, 7 additions, 4 negations
    let xcp = self.x * other.x;
    let ycp = self.y * other.y;
    let zcp = self.z * other.z;
    #[expect(non_snake_case)]
    let B = zcp.square();
    #[expect(non_snake_case)]
    let E = D * xcp * ycp;
    #[expect(non_snake_case)]
    let F = B - E;
    #[expect(non_snake_case)]
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
  #[expect(clippy::suspicious_arithmetic_impl)]
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
      let Some(point) = Option::<Self>::from(Self::from_bytes(&bytes)) else { continue };
      if !bool::from(point.is_identity()) {
        return point;
      }
    }
  }
  fn identity() -> Self {
    Point { x: FieldElement::ZERO, y: FieldElement::ONE, z: FieldElement::ONE }
  }
  fn generator() -> Self {
    G
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
    #[expect(non_snake_case)]
    let F = xsq + ysq;
    #[expect(non_snake_case)]
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
    Point::sum(iter.copied())
  }
}

impl Mul<Scalar> for Point {
  type Output = Point;
  fn mul(self, mut other: Scalar) -> Point {
    // Precompute the optimal amount that's a multiple of 2
    let mut table = [Point::identity(); 16];
    table[1] = self;
    for i in 2 .. 16 {
      table[i] = table[i - 1] + self;
    }

    let mut res = Self::identity();
    let mut bits = 0;
    for (i, mut bit) in other.to_le_bits().iter_mut().rev().enumerate() {
      bits <<= 1;
      let mut bit = u8_from_bool(&mut bit);
      bits |= bit;
      bit.zeroize();

      if ((i + 1) % 4) == 0 {
        if i != 3 {
          for _ in 0 .. 4 {
            res = res.double();
          }
        }

        let mut add_by = Point::identity();
        #[expect(clippy::needless_range_loop)]
        for i in 0 .. 16 {
          #[expect(clippy::cast_possible_truncation, clippy::as_conversions)] // Safe since 0 .. 16
          {
            add_by = <_>::conditional_select(&add_by, &table[i], bits.ct_eq(&(i as u8)));
          }
        }
        res += add_by;
        bits = 0;
      }
    }
    other.zeroize();
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
    ((*self * (Scalar::ZERO - Scalar::ONE)) + self).is_identity()
  }
}

impl GroupEncoding for Point {
  type Repr = <FieldElement as PrimeField>::Repr;

  fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
    // Extract and clear the sign bit
    let sign = Choice::from(bytes.as_ref()[56] >> 7);
    let mut bytes = *bytes;
    let mut_ref: &mut [u8] = bytes.as_mut();
    mut_ref[56] &= !(1 << 7);

    // Parse y, recover x
    FieldElement::from_repr(bytes).and_then(|y| {
      recover_x(y).and_then(|mut x| {
        x.conditional_negate(x.is_odd().ct_eq(&!sign));
        let not_negative_zero = !(x.is_zero() & sign);
        let point = Point { x, y, z: FieldElement::ONE };
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
  ff_group_tests::group::test_prime_group_bits::<_, Point>(&mut rand_core::OsRng);
}

#[test]
fn generator() {
  assert!(G.x == G_X);
  assert!(G.y == G_Y);
  assert!(recover_x(G.y).unwrap() == G.x);
}

#[test]
fn torsion() {
  // Uses the originally suggested generator which had torsion
  const TORSIONED_Y: &str = "\
12796c1532041525945f322e414d434467cfd5c57c9a9af2473b2775\
8c921c4828b277ca5f2891fc4f3d79afdf29a64c72fb28b59c16fa51\
00";
  let mut repr = <FieldElement as PrimeField>::Repr::default();
  repr.as_mut().copy_from_slice(&hex::decode(TORSIONED_Y).unwrap());

  let old_y = FieldElement::from_repr(repr).unwrap();
  let old = Point { x: -recover_x(old_y).unwrap(), y: old_y, z: FieldElement::ONE };
  assert!(bool::from(!old.is_torsion_free()));

  assert!(bool::from(Point::from_bytes(&old.to_bytes()).is_none()));
}

#[test]
fn vector() {
  const TWO_G: &str = "\
ed8693eacdfbeada6ba0cdd1beb2bcbb98302a3a8365650db8c4d88a\
726de3b7d74d8835a0d76e03b0c2865020d659b38d04d74a63e905ae\
80";
  let mut two_g = <Point as GroupEncoding>::Repr::default();
  two_g.as_mut().copy_from_slice(&hex::decode(TWO_G).unwrap());
  assert_eq!(Point::generator().double(), Point::from_bytes(&two_g).unwrap());

  const SCALAR: &str = "\
6298e1eef3c379392caaed061ed8a31033c9e9e3420726f23b404158\
a401cd9df24632adfe6b418dc942d8a091817dd8bd70e1c72ba52f3c\
00";
  let mut scalar = <Scalar as PrimeField>::Repr::default();
  scalar.as_mut().copy_from_slice(&hex::decode(SCALAR).unwrap());

  const SCALED_G: &str = "\
3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba2\
65632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b0\
00";
  let mut scaled_g = <Point as GroupEncoding>::Repr::default();
  scaled_g.as_mut().copy_from_slice(&hex::decode(SCALED_G).unwrap());

  assert_eq!(
    Point::generator() * Scalar::from_repr(scalar).unwrap(),
    Point::from_bytes(&scaled_g).unwrap()
  );
}

// Checks random won't infinitely loop
#[test]
fn random() {
  Point::random(&mut rand_core::OsRng);
}
