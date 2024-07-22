use core::{
  ops::{DerefMut, Add, AddAssign, Neg, Sub, SubAssign, Mul, MulAssign},
  iter::Sum,
};

use rand_core::RngCore;

use zeroize::Zeroize;
use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable, ConditionallyNegatable};

use generic_array::{typenum::U33, GenericArray};

use group::{
  ff::{Field, PrimeField, PrimeFieldBits},
  Group, GroupEncoding,
  prime::PrimeGroup,
};

use crate::{backend::u8_from_bool, Scalar, FieldElement};

fn recover_y(x: FieldElement) -> CtOption<FieldElement> {
  // x**3 + B since a = 0
  ((x.square() * x) + FieldElement::from(7u64)).sqrt()
}

/// Point.
#[derive(Clone, Copy, Debug, Zeroize)]
#[repr(C)]
pub struct Point {
  x: FieldElement, // / Z
  y: FieldElement, // / Z
  z: FieldElement,
}

impl ConstantTimeEq for Point {
  fn ct_eq(&self, other: &Self) -> Choice {
    let x1 = self.x * other.z;
    let x2 = other.x * self.z;

    let y1 = self.y * other.z;
    let y2 = other.y * self.z;

    (self.x.is_zero() & other.x.is_zero()) | (x1.ct_eq(&x2) & y1.ct_eq(&y2))
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
  #[allow(non_snake_case)]
  fn add(self, other: Self) -> Self {
    // add-2015-rcb

    let a = FieldElement::ZERO;
    let B = FieldElement::from(7u64);
    let b3 = B + B + B;

    let X1 = self.x;
    let Y1 = self.y;
    let Z1 = self.z;
    let X2 = other.x;
    let Y2 = other.y;
    let Z2 = other.z;

    let t0 = X1 * X2;
    let t1 = Y1 * Y2;
    let t2 = Z1 * Z2;
    let t3 = X1 + Y1;
    let t4 = X2 + Y2;
    let t3 = t3 * t4;
    let t4 = t0 + t1;
    let t3 = t3 - t4;
    let t4 = X1 + Z1;
    let t5 = X2 + Z2;
    let t4 = t4 * t5;
    let t5 = t0 + t2;
    let t4 = t4 - t5;
    let t5 = Y1 + Z1;
    let X3 = Y2 + Z2;
    let t5 = t5 * X3;
    let X3 = t1 + t2;
    let t5 = t5 - X3;
    let Z3 = a * t4;
    let X3 = b3 * t2;
    let Z3 = X3 + Z3;
    let X3 = t1 - Z3;
    let Z3 = t1 + Z3;
    let Y3 = X3 * Z3;
    let t1 = t0 + t0;
    let t1 = t1 + t0;
    let t2 = a * t2;
    let t4 = b3 * t4;
    let t1 = t1 + t2;
    let t2 = t0 - t2;
    let t2 = a * t2;
    let t4 = t4 + t2;
    let t0 = t1 * t4;
    let Y3 = Y3 + t0;
    let t0 = t5 * t4;
    let X3 = t3 * X3;
    let X3 = X3 - t0;
    let t0 = t3 * t1;
    let Z3 = t5 * Z3;
    let Z3 = Z3 + t0;
    Point { x: X3, y: Y3, z: Z3 }
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
    Point { x: self.x, y: -self.y, z: self.z }
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
      let mut bytes = GenericArray::default();
      rng.fill_bytes(bytes.as_mut());
      let opt = Self::from_bytes(&bytes);
      if opt.is_some().into() {
        return opt.unwrap();
      }
    }
  }
  fn identity() -> Self {
    Point { x: FieldElement::ZERO, y: FieldElement::ONE, z: FieldElement::ZERO }
  }
  fn generator() -> Self {
    Point {
      x: FieldElement::from_repr(
        hex_literal::hex!("0000000000000000000000000000000000000000000000000000000000000001")
          .into(),
      )
      .unwrap(),
      y: FieldElement::from_repr(
        hex_literal::hex!("0C7C97045A2074634909ABDF82C9BD0248916189041F2AF0C1B800D1FFC278C0")
          .into(),
      )
      .unwrap(),
      z: FieldElement::ONE,
    }
  }
  fn is_identity(&self) -> Choice {
    self.z.ct_eq(&FieldElement::ZERO)
  }
  #[allow(non_snake_case)]
  fn double(&self) -> Self {
    // dbl-2007-bl

    let a = FieldElement::ZERO;

    let X1 = self.x;
    let Y1 = self.y;
    let Z1 = self.z;

    let XX = X1 * X1;
    let ZZ = Z1 * Z1;
    let w = (a * ZZ) + XX.double() + XX;
    let s = (Y1 * Z1).double();
    let ss = s * s;
    let sss = s * ss;
    let R = Y1 * s;
    let RR = R * R;
    let B = X1 + R;
    let B = (B * B) - XX - RR;
    let h = (w * w) -  B.double();
    let X3 = h * s;
    let Y3 = w * (B - h) - RR.double();
    let Z3 = sss;

    let res = Self { x: X3, y: Y3, z: Z3 };
    // If self is identity, res will not be well-formed
    // Accordingly, we return self if self was the identity
    Self::conditional_select(&res, self, self.is_identity())
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
      let mut bit = u8_from_bool(bit.deref_mut());
      bits |= bit;
      bit.zeroize();

      if ((i + 1) % 4) == 0 {
        if i != 3 {
          for _ in 0 .. 4 {
            res = res.double();
          }
        }

        let mut term = table[0];
        for (j, candidate) in table[1 ..].iter().enumerate() {
          let j = j + 1;
          term = Self::conditional_select(&term, candidate, usize::from(bits).ct_eq(&j));
        }
        res += term;
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

impl GroupEncoding for Point {
  type Repr = GenericArray<u8, U33>;

  fn from_bytes(bytes: &Self::Repr) -> CtOption<Self> {
    // Extract and clear the sign bit
    let sign = Choice::from(bytes[0] & 1);

    // Parse x, recover y
    FieldElement::from_repr(*GenericArray::from_slice(&bytes[1 ..])).and_then(|x| {
      let is_identity = x.is_zero();

      let y = recover_y(x).map(|mut y| {
        y.conditional_negate(y.is_odd().ct_eq(&!sign));
        y
      });

      // If this the identity, set y to 1
      let y =
        CtOption::conditional_select(&y, &CtOption::new(FieldElement::ONE, 1.into()), is_identity);
      // Create the point if we have a y solution
      let point = y.map(|y| Point { x, y, z: FieldElement::ONE });

      let not_negative_zero = !(is_identity & sign);
      // Only return the point if it isn't -0 and the sign byte wasn't malleated
      CtOption::conditional_select(
        &CtOption::new(Point::identity(), 0.into()),
        &point,
        not_negative_zero & ((bytes[0] & 1).ct_eq(&bytes[0])),
      )
    })
  }

  fn from_bytes_unchecked(bytes: &Self::Repr) -> CtOption<Self> {
    Point::from_bytes(bytes)
  }

  fn to_bytes(&self) -> Self::Repr {
    let Some(z) = Option::<FieldElement>::from(self.z.invert()) else {
      return *GenericArray::from_slice(&[0; 33]);
    };
    let x = self.x * z;
    let y = self.y * z;

    let mut res = *GenericArray::from_slice(&[0; 33]);
    res[1 ..].as_mut().copy_from_slice(&x.to_repr());

    // The following conditional select normalizes the sign to 0 when x is 0
    let y_sign = u8::conditional_select(&y.is_odd().unwrap_u8(), &0, x.ct_eq(&FieldElement::ZERO));
    res[0] |= y_sign;
    res
  }
}

impl PrimeGroup for Point {}

impl ec_divisors::DivisorCurve for Point {
  type FieldElement = FieldElement;

  fn a() -> Self::FieldElement {
    FieldElement::from(0u64)
  }
  fn b() -> Self::FieldElement {
    FieldElement::from(7u64)
  }

  fn to_xy(point: Self) -> Option<(Self::FieldElement, Self::FieldElement)> {
    let z: Self::FieldElement = Option::from(point.z.invert())?;
    Some((point.x * z, point.y * z))
  }
}

#[test]
fn test_curve() {
  ff_group_tests::group::test_prime_group_bits::<_, Point>(&mut rand_core::OsRng);
}

#[test]
fn generator() {
  assert_eq!(
    Point::generator(),
    Point::from_bytes(GenericArray::from_slice(&hex_literal::hex!(
      "000000000000000000000000000000000000000000000000000000000000000001"
    )))
    .unwrap()
  );
}

#[test]
fn zero_x_is_invalid() {
  assert!(Option::<FieldElement>::from(recover_y(FieldElement::ZERO)).is_none());
}

// Checks random won't infinitely loop
#[test]
fn random() {
  Point::random(&mut rand_core::OsRng);
}
