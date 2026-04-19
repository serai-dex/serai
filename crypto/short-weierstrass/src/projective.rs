use core::{hint::black_box, borrow::Borrow, ops::*, iter::Sum};

use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable, ConditionallyNegatable};
use zeroize::{Zeroize as _, DefaultIsZeroes};

use rand_core::RngCore;

use group::{
  ff::{Field as _, PrimeField as _, PrimeFieldBits},
  Group, GroupEncoding,
  prime::PrimeGroup,
};

use crate::{ShortWeierstrass, Affine};

/// A point represented with projective coordinates.
#[derive(Debug)]
pub struct Projective<C: ShortWeierstrass> {
  pub(crate) x: C::FieldElement,
  pub(crate) y: C::FieldElement,
  pub(crate) z: C::FieldElement,
}
impl<C: ShortWeierstrass> Clone for Projective<C> {
  fn clone(&self) -> Self {
    *self
  }
}
impl<C: ShortWeierstrass> Copy for Projective<C> {}

impl<C: ShortWeierstrass> From<Affine<C>> for Projective<C> {
  fn from(affine: Affine<C>) -> Self {
    Self { x: affine.x, y: affine.y, z: C::FieldElement::ONE }
  }
}

impl<C: ShortWeierstrass> Default for Projective<C> {
  fn default() -> Self {
    Self::IDENTITY
  }
}
impl<C: ShortWeierstrass> DefaultIsZeroes for Projective<C> {}

impl<C: ShortWeierstrass> ConstantTimeEq for Projective<C> {
  fn ct_eq(&self, other: &Self) -> Choice {
    let c1 = (self.x * other.z).ct_eq(&(other.x * self.z));
    let c2 = (self.y * other.z).ct_eq(&(other.y * self.z));
    c1 & c2
  }
}
impl<C: ShortWeierstrass> PartialEq for Projective<C> {
  fn eq(&self, other: &Self) -> bool {
    self.ct_eq(other).into()
  }
}
impl<C: ShortWeierstrass> Eq for Projective<C> {}

impl<C: ShortWeierstrass> ConditionallySelectable for Projective<C> {
  #[expect(clippy::many_single_char_names)]
  fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
    let x = C::FieldElement::conditional_select(&a.x, &b.x, choice);
    let y = C::FieldElement::conditional_select(&a.y, &b.y, choice);
    let z = C::FieldElement::conditional_select(&a.z, &b.z, choice);
    Projective { x, y, z }
  }
}

impl<C: ShortWeierstrass> Neg for Projective<C> {
  type Output = Self;
  fn neg(mut self) -> Self::Output {
    self.y = -self.y;
    self
  }
}

impl<C: ShortWeierstrass> ConditionallyNegatable for Projective<C> {
  fn conditional_negate(&mut self, negate: Choice) {
    self.y = <_>::conditional_select(&self.y, &-self.y, negate);
  }
}

impl<C: ShortWeierstrass> Projective<C> {
  // add-1998-cmo-2
  fn add_if_composite_order(self, other: Self) -> Self {
    let Self { x: X1, y: Y1, z: Z1 } = self;
    let Self { x: X2, y: Y2, z: Z2 } = other;

    let Y1Z2 = Y1 * Z2;
    let X1Z2 = X1 * Z2;
    let Z1Z2 = Z1 * Z2;
    let u = (Y2 * Z1) - Y1Z2;
    let uu = u.square();
    let v = (X2 * Z1) - X1Z2;
    let vv = v.square();
    let vvv = v * vv;
    let R = vv * X1Z2;
    let A = (uu * Z1Z2) - vvv - R.double();
    let X3 = v * A;
    let Y3 = (u * (R - A)) - (vvv * Y1Z2);
    let Z3 = vvv * Z1Z2;

    let res = Self { x: X3, y: Y3, z: Z3 };

    let same_x_coordinate = (self.x * other.z).ct_eq(&(other.x * self.z));
    let same_y_coordinate = (self.y * other.z).ct_eq(&(other.y * self.z));
    let res = <_>::conditional_select(
      &res,
      &Self::IDENTITY,
      (self.is_identity_internal() & other.is_identity_internal()) |
        (same_x_coordinate & (!same_y_coordinate)),
    );
    let res =
      <_>::conditional_select(&res, &self.double_internal(), same_x_coordinate & same_y_coordinate);
    let res = <_>::conditional_select(&res, &other, self.is_identity_internal());
    <_>::conditional_select(&res, &self, other.is_identity_internal())
  }

  // add-2015-rcb
  fn add_if_prime_order(self, other: Self) -> Self {
    let b3 = C::B + C::B + C::B;

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
    let Z3 = C::A * t4;
    let X3 = b3 * t2;
    let Z3 = X3 + Z3;
    let X3 = t1 - Z3;
    let Z3 = t1 + Z3;
    let Y3 = X3 * Z3;
    let t1 = t0 + t0;
    let t1 = t1 + t0;
    let t2 = C::A * t2;
    let t4 = b3 * t4;
    let t1 = t1 + t2;
    let t2 = t0 - t2;
    let t2 = C::A * t2;
    let t4 = t4 + t2;
    let t0 = t1 * t4;
    let Y3 = Y3 + t0;
    let t0 = t5 * t4;
    let X3 = t3 * X3;
    let X3 = X3 - t0;
    let t0 = t3 * t1;
    let Z3 = t5 * Z3;
    let Z3 = Z3 + t0;

    Projective { x: X3, y: Y3, z: Z3 }
  }
}

impl<C: ShortWeierstrass> Add for Projective<C> {
  type Output = Self;
  fn add(self, other: Self) -> Self {
    if C::PRIME_ORDER {
      self.add_if_prime_order(other)
    } else {
      self.add_if_composite_order(other)
    }
  }
}
impl<C: ShortWeierstrass> Sub for Projective<C> {
  type Output = Self;
  fn sub(self, p2: Self) -> Self {
    self + -p2
  }
}
impl<C: ShortWeierstrass> AddAssign for Projective<C> {
  fn add_assign(&mut self, p2: Self) {
    *self = *self + p2;
  }
}
impl<C: ShortWeierstrass> SubAssign for Projective<C> {
  fn sub_assign(&mut self, p2: Self) {
    *self = *self - p2;
  }
}
impl<C: ShortWeierstrass> Add<&Self> for Projective<C> {
  type Output = Self;
  fn add(self, p2: &Self) -> Self {
    self + *p2
  }
}
impl<C: ShortWeierstrass> Sub<&Self> for Projective<C> {
  type Output = Self;
  fn sub(self, p2: &Self) -> Self {
    self - *p2
  }
}
impl<C: ShortWeierstrass> AddAssign<&Self> for Projective<C> {
  fn add_assign(&mut self, p2: &Self) {
    *self = *self + p2;
  }
}
impl<C: ShortWeierstrass> SubAssign<&Self> for Projective<C> {
  fn sub_assign(&mut self, p2: &Self) {
    *self = *self - p2;
  }
}

impl<C: ShortWeierstrass> Projective<C> {
  /// The additive identity, or point at infinity.
  pub const IDENTITY: Self =
    Projective { x: C::FieldElement::ZERO, y: C::FieldElement::ONE, z: C::FieldElement::ZERO };
  /// A generator of this elliptic curve.
  pub const GENERATOR: Self =
    Projective { x: C::GENERATOR.x, y: C::GENERATOR.y, z: C::FieldElement::ONE };

  fn is_identity_internal(&self) -> Choice {
    self.z.ct_eq(&C::FieldElement::ZERO)
  }

  // dbl-1998-cmo-2
  fn double_internal(&self) -> Self {
    let Self { x: X1, y: Y1, z: Z1 } = *self;

    let X1X1 = X1.square();
    let w = (C::A * Z1.square()) + X1X1.double() + X1X1;
    let s = Y1 * Z1;
    let ss = s.square();
    let sss = s * ss;
    let R = Y1 * s;
    let B = X1 * R;
    let B4 = B.double().double();
    let h = w.square() - B4.double();
    let X3 = (h * s).double();
    let Y3 = w * (B4 - h) - R.square().double().double().double();
    let Z3 = sss.double().double().double();

    let res = Self { x: X3, y: Y3, z: Z3 };
    <_>::conditional_select(&res, &Self::IDENTITY, self.is_identity_internal())
  }
}

impl<C: ShortWeierstrass> Sum for Projective<C> {
  fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
    let mut res = Self::IDENTITY;
    for item in iter {
      res += item;
    }
    res
  }
}

impl<'a, C: ShortWeierstrass> Sum<&'a Self> for Projective<C> {
  fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
    let mut res = Self::IDENTITY;
    for item in iter {
      res += item;
    }
    res
  }
}

impl<C: ShortWeierstrass<Scalar: PrimeFieldBits>, S: Borrow<C::Scalar>> Mul<S> for Projective<C> {
  type Output = Self;
  fn mul(self, scalar: S) -> Self {
    let mut table = [Self::IDENTITY; 16];
    table[1] = self;
    for i in 2 .. 16 {
      table[i] = table[i - 1] + self;
    }

    let mut res = Self::identity();
    let mut bits = 0;
    for (i, mut bit) in scalar.borrow().to_le_bits().iter_mut().rev().enumerate() {
      fn u8_from_bool(bit_ref: &mut bool) -> u8 {
        let bit_ref = black_box(bit_ref);

        let mut bit = black_box(*bit_ref);
        let res = black_box(u8::from(bit));
        bit.zeroize();
        debug_assert!((res | 1) == 1);

        bit_ref.zeroize();
        res
      }

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
    res
  }
}
impl<C: ShortWeierstrass<Scalar: PrimeFieldBits>, S: Borrow<C::Scalar>> MulAssign<S>
  for Projective<C>
{
  fn mul_assign(&mut self, scalar: S) {
    *self = *self * scalar.borrow();
  }
}
impl<C: ShortWeierstrass<Scalar: PrimeFieldBits>> Group for Projective<C> {
  type Scalar = C::Scalar;
  fn random(rng: impl RngCore) -> Self {
    Self::from(Affine::<C>::random(rng))
  }
  fn identity() -> Self {
    Self::IDENTITY
  }
  fn generator() -> Self {
    C::GENERATOR.into()
  }
  fn is_identity(&self) -> Choice {
    self.is_identity_internal()
  }
  fn double(&self) -> Self {
    self.double_internal()
  }
}

impl<C: ShortWeierstrass> GroupEncoding for Projective<C> {
  type Repr = C::Repr;
  fn from_bytes(bytes: &C::Repr) -> CtOption<Self> {
    // If this point is the identity point
    let identity = bytes.as_ref().ct_eq(C::IDENTITY.as_ref());

    let (x, odd_y) = C::decode_compressed(bytes);

    let result = C::FieldElement::from_repr(x)
      .and_then(|x| Affine::decompress(x, odd_y).map(Projective::from));
    // Set the identity, if the identity
    let identity = CtOption::new(Projective::IDENTITY, identity);
    let result = result.or_else(|| identity);

    let mut result_is_valid = result.is_some();
    let result = result.unwrap_or(Projective::IDENTITY);
    // Constrain points to the prime-order subgroup
    result_is_valid &= !C::has_torsion_element(result);

    CtOption::new(result, result_is_valid)
  }
  fn from_bytes_unchecked(bytes: &C::Repr) -> CtOption<Self> {
    Self::from_bytes(bytes)
  }
  fn to_bytes(&self) -> C::Repr {
    let affine_on_curve = Affine::try_from(self);
    let identity = affine_on_curve.is_none();

    let compressed_if_not_identity = {
      let affine_on_curve = affine_on_curve.unwrap_or(C::GENERATOR);
      let (x, y) = affine_on_curve.coordinates();
      C::encode_compressed(x, y.is_odd())
    };

    let mut res = C::Repr::default();
    {
      let res = res.as_mut();
      for (dst, (if_not_identity, if_identity)) in
        res.iter_mut().zip(compressed_if_not_identity.as_ref().iter().zip(C::IDENTITY.as_ref()))
      {
        *dst = <_>::conditional_select(if_not_identity, if_identity, identity);
      }
    }
    res
  }
}

/// We implement `PrimeGroup` due to constraining to a prime-order subgroup
impl<C: ShortWeierstrass<Scalar: PrimeFieldBits>> PrimeGroup for Projective<C> {}

#[cfg(feature = "alloc")]
mod alloc {
  use ff::{PrimeField, PrimeFieldBits};
  use crate::{ShortWeierstrass, Affine, Projective};

  impl<C: ShortWeierstrass<Scalar: PrimeFieldBits>> ec_divisors::DivisorCurve for Projective<C> {
    type FieldElement = C::FieldElement;
    type XyPoint = ec_divisors::Projective<Self>;

    type BorrowedInterpolator = ec_divisors::Interpolator<C::FieldElement>;
    fn interpolator_for_scalar_mul() -> Self::BorrowedInterpolator {
      #[expect(clippy::as_conversions)]
      ec_divisors::Interpolator::new((<C::Scalar as PrimeField>::NUM_BITS as usize).div_ceil(2) + 2)
    }

    fn a() -> C::FieldElement {
      C::A
    }
    fn b() -> C::FieldElement {
      C::B
    }

    fn to_xy(point: Self) -> Option<(C::FieldElement, C::FieldElement)> {
      Option::<Affine<C>>::from(Affine::try_from(&point)).map(Affine::<_>::coordinates)
    }
  }
}
