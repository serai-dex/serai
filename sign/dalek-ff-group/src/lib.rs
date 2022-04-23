use core::{
  ops::{Deref, Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign},
  borrow::Borrow,
  iter::{Iterator, Sum}
};

use rand_core::RngCore;

use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable};

pub use curve25519_dalek as dalek;

use dalek::{
  constants,
  traits::Identity,
  scalar::Scalar as DScalar,
  edwards::{
    EdwardsPoint as DPoint,
    EdwardsBasepointTable as DTable,
    CompressedEdwardsY as DCompressed
  }
};

use ff::{Field, PrimeField};
use group::Group;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Scalar(pub DScalar);

impl Deref for Scalar {
  type Target = DScalar;

  fn deref(&self) -> &Self::Target {
    &self.0
  }
}

impl Borrow<DScalar> for Scalar {
  fn borrow(&self) -> &DScalar {
    &self.0
  }
}

impl Borrow<DScalar> for &Scalar {
  fn borrow(&self) -> &DScalar {
    &self.0
  }
}

impl Add<Scalar> for Scalar {
  type Output = Self;
  fn add(self, other: Scalar) -> Scalar { Self(self.0 + other.0) }
}
impl AddAssign for Scalar {
  fn add_assign(&mut self, other: Scalar) { self.0 += other.0 }
}

impl<'a> Add<&'a Scalar> for Scalar {
  type Output = Self;
  fn add(self, other: &'a Scalar) -> Scalar { Self(self.0 + other.0) }
}
impl<'a> AddAssign<&'a Scalar> for Scalar {
  fn add_assign(&mut self, other: &'a Scalar) { self.0 += other.0 }
}

impl Sub<Scalar> for Scalar {
  type Output = Self;
  fn sub(self, other: Scalar) -> Scalar { Self(self.0 - other.0) }
}
impl SubAssign for Scalar {
  fn sub_assign(&mut self, other: Scalar) { self.0 -= other.0 }
}

impl<'a> Sub<&'a Scalar> for Scalar {
  type Output = Self;
  fn sub(self, other: &'a Scalar) -> Scalar { Self(self.0 - other.0) }
}
impl<'a> SubAssign<&'a Scalar> for Scalar {
  fn sub_assign(&mut self, other: &'a Scalar) { self.0 -= other.0 }
}

impl Neg for Scalar {
  type Output = Self;
  fn neg(self) -> Scalar { Self(-self.0) }
}

impl Mul<Scalar> for Scalar {
  type Output = Self;
  fn mul(self, other: Scalar) -> Scalar { Self(self.0 * other.0) }
}
impl MulAssign for Scalar {
  fn mul_assign(&mut self, other: Scalar) { self.0 *= other.0 }
}

impl<'a> Mul<&'a Scalar> for Scalar {
  type Output = Self;
  fn mul(self, other: &'a Scalar) -> Scalar { Self(self.0 * other.0) }
}
impl<'a> MulAssign<&'a Scalar> for Scalar {
  fn mul_assign(&mut self, other: &'a Scalar) { self.0 *= other.0 }
}

impl ConstantTimeEq for Scalar {
  fn ct_eq(&self, _: &Self) -> Choice { unimplemented!() }
}

impl ConditionallySelectable for Scalar {
  fn conditional_select(_: &Self, _: &Self, _: Choice) -> Self { unimplemented!() }
}

impl Field for Scalar {
  fn random(mut rng: impl RngCore) -> Self {
    let mut r = [0; 64];
    rng.fill_bytes(&mut r);
    Self(DScalar::from_bytes_mod_order_wide(&r))
  }

  fn zero() -> Self { Self(DScalar::zero()) }
  fn one() -> Self { Self(DScalar::one()) }
  fn square(&self) -> Self { *self * self }
  fn double(&self) -> Self { *self + self }
  fn invert(&self) -> CtOption<Self> { CtOption::new(Self(self.0.invert()), Choice::from(1 as u8)) }
  fn sqrt(&self) -> CtOption<Self> { unimplemented!() }
  fn is_zero(&self) -> Choice { Choice::from(if self.0 == DScalar::zero() { 1 } else { 0 }) }
  fn cube(&self) -> Self { *self * self * self }
  fn pow_vartime<S: AsRef<[u64]>>(&self, _exp: S) -> Self { unimplemented!() }
}

impl From<u64> for Scalar {
  fn from(a: u64) -> Scalar { Self(DScalar::from(a)) }
}

impl PrimeField for Scalar {
  type Repr = [u8; 32];
  const NUM_BITS: u32 = 253;
  const CAPACITY: u32 = 252;
  fn from_repr(bytes: [u8; 32]) -> CtOption<Self> {
    let scalar = DScalar::from_canonical_bytes(bytes).map(|x| Scalar(x));
    CtOption::new(scalar.unwrap_or(Scalar::zero()), Choice::from(if scalar.is_some() { 1 } else { 0 }))
  }
  fn to_repr(&self) -> [u8; 32] { self.0.to_bytes() }

  const S: u32 = 0;
  fn is_odd(&self) -> Choice { unimplemented!() }
  fn multiplicative_generator() -> Self { unimplemented!() }
  fn root_of_unity() -> Self { unimplemented!() }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EdwardsPoint(pub DPoint);
pub const ED25519_BASEPOINT_POINT: EdwardsPoint = EdwardsPoint(constants::ED25519_BASEPOINT_POINT);

impl Deref for EdwardsPoint {
    type Target = DPoint;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<DPoint> for EdwardsPoint {
  fn borrow(&self) -> &DPoint {
    &self.0
  }
}

impl Borrow<DPoint> for &EdwardsPoint {
  fn borrow(&self) -> &DPoint {
    &self.0
  }
}

impl Add<EdwardsPoint> for EdwardsPoint {
  type Output = Self;
  fn add(self, b: EdwardsPoint) -> EdwardsPoint { Self(self.0 + b.0) }
}
impl AddAssign<EdwardsPoint> for EdwardsPoint {
  fn add_assign(&mut self, other: EdwardsPoint) { self.0 += other.0 }
}
impl Sum<EdwardsPoint> for EdwardsPoint {
  fn sum<I: Iterator<Item = EdwardsPoint>>(iter: I) -> EdwardsPoint { Self(DPoint::sum(iter)) }
}

impl<'a> Add<&'a EdwardsPoint> for EdwardsPoint {
  type Output = Self;
  fn add(self, b: &'a EdwardsPoint) -> EdwardsPoint { Self(self.0 + b.0) }
}
impl<'a> AddAssign<&'a EdwardsPoint> for EdwardsPoint {
  fn add_assign(&mut self, other: &'a EdwardsPoint) { self.0 += other.0 }
}
impl<'a> Sum<&'a EdwardsPoint> for EdwardsPoint {
  fn sum<I: Iterator<Item = &'a EdwardsPoint>>(iter: I) -> EdwardsPoint { Self(DPoint::sum(iter)) }
}

impl Sub<EdwardsPoint> for EdwardsPoint {
  type Output = Self;
  fn sub(self, b: EdwardsPoint) -> EdwardsPoint { Self(self.0 - b.0) }
}
impl SubAssign<EdwardsPoint> for EdwardsPoint {
  fn sub_assign(&mut self, other: EdwardsPoint) { self.0 -= other.0 }
}

impl<'a> Sub<&'a EdwardsPoint> for EdwardsPoint {
  type Output = Self;
  fn sub(self, b: &'a EdwardsPoint) -> EdwardsPoint { Self(self.0 - b.0) }
}
impl<'a> SubAssign<&'a EdwardsPoint> for EdwardsPoint {
  fn sub_assign(&mut self, other: &'a EdwardsPoint) { self.0 -= other.0 }
}

impl Neg for EdwardsPoint {
  type Output = Self;
  fn neg(self) -> EdwardsPoint { Self(-self.0) }
}

impl Mul<Scalar> for EdwardsPoint {
  type Output = Self;
  fn mul(self, b: Scalar) -> EdwardsPoint { Self(b.0 * self.0) }
}
impl MulAssign<Scalar> for EdwardsPoint {
  fn mul_assign(&mut self, other: Scalar) { self.0 *= other.0 }
}

impl<'a> Mul<&'a Scalar> for EdwardsPoint {
  type Output = Self;
  fn mul(self, b: &'a Scalar) -> EdwardsPoint { Self(b.0 * self.0) }
}
impl<'a> MulAssign<&'a Scalar> for EdwardsPoint {
  fn mul_assign(&mut self, other: &'a Scalar) { self.0 *= other.0 }
}

impl Group for EdwardsPoint {
  type Scalar = Scalar;
  fn random(mut _rng: impl RngCore) -> Self { unimplemented!() }
  fn identity() -> Self { Self(DPoint::identity()) }
  fn generator() -> Self { ED25519_BASEPOINT_POINT }
  fn is_identity(&self) -> Choice { unimplemented!() }
  fn double(&self) -> Self { *self + self }
}

impl Scalar {
  pub fn from_canonical_bytes(bytes: [u8; 32]) -> Option<Scalar> {
    DScalar::from_canonical_bytes(bytes).map(|x| Self(x))
  }
  pub fn from_bytes_mod_order(bytes: [u8; 32]) -> Scalar {
    Self(DScalar::from_bytes_mod_order(bytes))
  }
  pub fn from_bytes_mod_order_wide(bytes: &[u8; 64]) -> Scalar {
    Self(DScalar::from_bytes_mod_order_wide(bytes))
  }
}

pub struct CompressedEdwardsY(pub DCompressed);
impl CompressedEdwardsY {
  pub fn new(y: [u8; 32]) -> CompressedEdwardsY {
    Self(DCompressed(y))
  }

  pub fn decompress(&self) -> Option<EdwardsPoint> {
    self.0.decompress().map(|x| EdwardsPoint(x))
  }

  pub fn to_bytes(&self) -> [u8; 32] {
    self.0.to_bytes()
  }
}

impl EdwardsPoint {
  pub fn is_torsion_free(&self) -> bool {
    self.0.is_torsion_free()
  }

  pub fn compress(&self) -> CompressedEdwardsY {
    CompressedEdwardsY(self.0.compress())
  }
}

pub struct EdwardsBasepointTable(pub DTable);
pub const ED25519_BASEPOINT_TABLE: EdwardsBasepointTable = EdwardsBasepointTable(constants::ED25519_BASEPOINT_TABLE);

impl Deref for EdwardsBasepointTable {
    type Target = DTable;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Borrow<DTable> for &EdwardsBasepointTable {
  fn borrow(&self) -> &DTable {
    &self.0
  }
}

impl Mul<Scalar> for &EdwardsBasepointTable {
  type Output = EdwardsPoint;
  fn mul(self, b: Scalar) -> EdwardsPoint { EdwardsPoint(&b.0 * &self.0) }
}
