use core::{
  ops::{DerefMut, Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign},
  iter::{Sum, Product},
};

use zeroize::Zeroize;
use rand_core::RngCore;

use subtle::{
  Choice, CtOption, ConstantTimeEq, ConstantTimeLess, ConditionallyNegatable,
  ConditionallySelectable,
};

use crypto_bigint::{Integer, NonZero, Encoding, U256, U512};

use group::ff::{Field, PrimeField, FieldBits, PrimeFieldBits};

use crate::{u8_from_bool, constant_time, math, from_uint};

// 2^255 - 19
// Uses saturating_sub because checked_sub isn't available at compile time
const MODULUS: U256 = U256::from_u8(1).shl_vartime(255).saturating_sub(&U256::from_u8(19));
const WIDE_MODULUS: U512 = U256::ZERO.concat(&MODULUS);

/// A constant-time implementation of the Ed25519 field.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct FieldElement(U256);

/*
The following is a valid const definition of sqrt(-1) yet exceeds the const_eval_limit by 24x.
Accordingly, it'd only be usable on a nightly compiler with the following crate attributes:
#![feature(const_eval_limit)]
#![const_eval_limit = "24000000"]

const SQRT_M1: FieldElement = {
  // Formula from RFC-8032 (modp_sqrt_m1/sqrt8k5 z)
  // 2 ** ((MODULUS - 1) // 4) % MODULUS
  let base = U256::from_u8(2);
  let exp = MODULUS.saturating_sub(&U256::from_u8(1)).wrapping_div(&U256::from_u8(4));

  const fn mul(x: U256, y: U256) -> U256 {
    let wide = U256::mul_wide(&x, &y);
    let wide = U256::concat(&wide.1, &wide.0);
    wide.wrapping_rem(&WIDE_MODULUS).split().1
  }

  // Perform the pow via multiply and square
  let mut res = U256::ONE;
  // Iterate from highest bit to lowest bit
  let mut bit = 255;
  loop {
    if bit != 255 {
      res = mul(res, res);
    }

    // Reverse from little endian to big endian
    if exp.bit_vartime(bit) == 1 {
      res = mul(res, base);
    }

    if bit == 0 {
      break;
    }
    bit -= 1;
  }

  FieldElement(res)
};
*/

// Use a constant since we can't calculate it at compile-time without a nightly compiler
// Even without const_eval_limit, it'd take ~30s to calculate, which isn't worth it
const SQRT_M1: FieldElement = FieldElement(U256::from_be_hex(
  "2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0",
));

// Constant useful in calculating square roots (RFC-8032 sqrt8k5's exponent used to calculate y)
const MOD_3_8: FieldElement =
  FieldElement(MODULUS.saturating_add(&U256::from_u8(3)).wrapping_div(&U256::from_u8(8)));

// Constant useful in sqrt_ratio_i (sqrt(u / v))
const MOD_5_8: FieldElement = FieldElement(MOD_3_8.0.saturating_sub(&U256::ONE));

fn reduce(x: U512) -> U256 {
  U256::from_le_slice(&x.rem(&NonZero::new(WIDE_MODULUS).unwrap()).to_le_bytes()[.. 32])
}

constant_time!(FieldElement, U256);
math!(
  FieldElement,
  FieldElement,
  |x, y| U256::add_mod(&x, &y, &MODULUS),
  |x, y| U256::sub_mod(&x, &y, &MODULUS),
  |x, y| reduce(U512::from(U256::mul_wide(&x, &y)))
);
from_uint!(FieldElement, U256);

impl Neg for FieldElement {
  type Output = Self;
  fn neg(self) -> Self::Output {
    Self(self.0.neg_mod(&MODULUS))
  }
}

impl<'a> Neg for &'a FieldElement {
  type Output = FieldElement;
  fn neg(self) -> Self::Output {
    (*self).neg()
  }
}

impl Field for FieldElement {
  const ZERO: Self = Self(U256::ZERO);
  const ONE: Self = Self(U256::ONE);

  fn random(mut rng: impl RngCore) -> Self {
    let mut bytes = [0; 64];
    rng.fill_bytes(&mut bytes);
    FieldElement(reduce(U512::from_le_bytes(bytes)))
  }

  fn square(&self) -> Self {
    FieldElement(reduce(self.0.square()))
  }
  fn double(&self) -> Self {
    FieldElement((self.0 << 1).rem(&NonZero::new(MODULUS).unwrap()))
  }

  fn invert(&self) -> CtOption<Self> {
    const NEG_2: FieldElement = FieldElement(MODULUS.saturating_sub(&U256::from_u8(2)));
    CtOption::new(self.pow(NEG_2), !self.is_zero())
  }

  // RFC-8032 sqrt8k5
  fn sqrt(&self) -> CtOption<Self> {
    let tv1 = self.pow(MOD_3_8);
    let tv2 = tv1 * SQRT_M1;
    let candidate = Self::conditional_select(&tv2, &tv1, tv1.square().ct_eq(self));
    CtOption::new(candidate, candidate.square().ct_eq(self))
  }

  fn sqrt_ratio(u: &FieldElement, v: &FieldElement) -> (Choice, FieldElement) {
    let i = SQRT_M1;

    let u = *u;
    let v = *v;

    let v3 = v.square() * v;
    let v7 = v3.square() * v;
    let mut r = (u * v3) * (u * v7).pow(MOD_5_8);

    let check = v * r.square();
    let correct_sign = check.ct_eq(&u);
    let flipped_sign = check.ct_eq(&(-u));
    let flipped_sign_i = check.ct_eq(&((-u) * i));

    r.conditional_assign(&(r * i), flipped_sign | flipped_sign_i);

    let r_is_negative = r.is_odd();
    r.conditional_negate(r_is_negative);

    (correct_sign | flipped_sign, r)
  }
}

impl PrimeField for FieldElement {
  type Repr = [u8; 32];

  // Big endian representation of the modulus
  const MODULUS: &'static str = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";

  const NUM_BITS: u32 = 255;
  const CAPACITY: u32 = 254;

  const TWO_INV: Self = FieldElement(U256::from_be_hex(
    "3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7",
  ));

  // This was calculated with the method from the ff crate docs
  // SageMath GF(modulus).primitive_element()
  const MULTIPLICATIVE_GENERATOR: Self = Self(U256::from_u8(2));
  // This was set per the specification in the ff crate docs
  // The number of leading zero bits in the little-endian bit representation of (modulus - 1)
  const S: u32 = 2;

  // This was calculated via the formula from the ff crate docs
  // Self::multiplicative_generator() ** ((modulus - 1) >> Self::S)
  const ROOT_OF_UNITY: Self = FieldElement(U256::from_be_hex(
    "2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0",
  ));
  const ROOT_OF_UNITY_INV: Self = FieldElement(U256::from_be_hex(
    "547cdb7fb03e20f4d4b2ff66c2042858d0bce7f952d01b873b11e4d8b5f15f3d",
  ));

  // This was calculated via the formula from the ff crate docs
  // Self::MULTIPLICATIVE_GENERATOR ** (2 ** Self::S)
  const DELTA: Self = FieldElement(U256::from_be_hex(
    "0000000000000000000000000000000000000000000000000000000000000010",
  ));

  fn from_repr(bytes: [u8; 32]) -> CtOption<Self> {
    let res = Self(U256::from_le_bytes(bytes));
    CtOption::new(res, res.0.ct_lt(&MODULUS))
  }
  fn to_repr(&self) -> [u8; 32] {
    self.0.to_le_bytes()
  }

  fn is_odd(&self) -> Choice {
    self.0.is_odd()
  }

  fn from_u128(num: u128) -> Self {
    Self::from(num)
  }
}

impl PrimeFieldBits for FieldElement {
  type ReprBits = [u8; 32];

  fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
    self.to_repr().into()
  }

  fn char_le_bits() -> FieldBits<Self::ReprBits> {
    MODULUS.to_le_bytes().into()
  }
}

impl FieldElement {
  /// Interpret the value as a little-endian integer, square it, and reduce it into a FieldElement.
  pub fn from_square(value: [u8; 32]) -> FieldElement {
    let value = U256::from_le_bytes(value);
    FieldElement(value) * FieldElement(value)
  }

  /// Perform an exponentation.
  pub fn pow(&self, other: FieldElement) -> FieldElement {
    let mut table = [FieldElement::ONE; 16];
    table[1] = *self;
    for i in 2 .. 16 {
      table[i] = table[i - 1] * self;
    }

    let mut res = FieldElement::ONE;
    let mut bits = 0;
    for (i, mut bit) in other.to_le_bits().iter_mut().rev().enumerate() {
      bits <<= 1;
      let mut bit = u8_from_bool(bit.deref_mut());
      bits |= bit;
      bit.zeroize();

      if ((i + 1) % 4) == 0 {
        if i != 3 {
          for _ in 0 .. 4 {
            res *= res;
          }
        }
        res *= table[usize::from(bits)];
        bits = 0;
      }
    }
    res
  }

  /// The square root of u/v, as used for Ed25519 point decoding (RFC 8032 5.1.3) and within
  /// Ristretto (5.1 Extracting an Inverse Square Root).
  ///
  /// The result is only a valid square root if the Choice is true.
  /// RFC 8032 simply fails if there isn't a square root, leaving any return value undefined.
  /// Ristretto explicitly returns 0 or sqrt((SQRT_M1 * u) / v).
  pub fn sqrt_ratio_i(u: FieldElement, v: FieldElement) -> (Choice, FieldElement) {
    let i = SQRT_M1;

    let v3 = v.square() * v;
    let v7 = v3.square() * v;
    // Candidate root
    let mut r = (u * v3) * (u * v7).pow(MOD_5_8);

    // 8032 3.1
    let check = v * r.square();
    let correct_sign = check.ct_eq(&u);
    // 8032 3.2 conditional
    let neg_u = -u;
    let flipped_sign = check.ct_eq(&neg_u);
    // Ristretto Step 5
    let flipped_sign_i = check.ct_eq(&(neg_u * i));

    // 3.2 set
    r.conditional_assign(&(r * i), flipped_sign | flipped_sign_i);

    // Always return the even root, per Ristretto
    // This doesn't break Ed25519 point decoding as that doesn't expect these steps to return a
    // specific root
    // Ed25519 points include a dedicated sign bit to determine which root to use, so at worst
    // this is a pointless inefficiency
    r.conditional_negate(r.is_odd());

    (correct_sign | flipped_sign, r)
  }
}

impl Sum<FieldElement> for FieldElement {
  fn sum<I: Iterator<Item = FieldElement>>(iter: I) -> FieldElement {
    let mut res = FieldElement::ZERO;
    for item in iter {
      res += item;
    }
    res
  }
}

impl<'a> Sum<&'a FieldElement> for FieldElement {
  fn sum<I: Iterator<Item = &'a FieldElement>>(iter: I) -> FieldElement {
    iter.cloned().sum()
  }
}

impl Product<FieldElement> for FieldElement {
  fn product<I: Iterator<Item = FieldElement>>(iter: I) -> FieldElement {
    let mut res = FieldElement::ZERO;
    for item in iter {
      res *= item;
    }
    res
  }
}

impl<'a> Product<&'a FieldElement> for FieldElement {
  fn product<I: Iterator<Item = &'a FieldElement>>(iter: I) -> FieldElement {
    iter.cloned().product()
  }
}

#[test]
fn test_wide_modulus() {
  let mut wide = [0; 64];
  wide[.. 32].copy_from_slice(&MODULUS.to_le_bytes());
  assert_eq!(wide, WIDE_MODULUS.to_le_bytes());
}

#[test]
fn test_inv_consts() {
  assert_eq!(FieldElement::from(2u8).invert().unwrap(), FieldElement::TWO_INV);
  assert_eq!(FieldElement::ROOT_OF_UNITY.invert().unwrap(), FieldElement::ROOT_OF_UNITY_INV);
}

#[test]
fn test_delta() {
  assert_eq!(
    FieldElement::MULTIPLICATIVE_GENERATOR.pow(FieldElement::from(2u8).pow(FieldElement::S.into())),
    FieldElement::DELTA
  );
}

#[test]
fn test_sqrt_m1() {
  // Test equivalence against the known constant value
  const SQRT_M1_MAGIC: U256 =
    U256::from_be_hex("2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0");
  assert_eq!(SQRT_M1.0, SQRT_M1_MAGIC);

  // Also test equivalence against the result of the formula from RFC-8032 (modp_sqrt_m1/sqrt8k5 z)
  // 2 ** ((MODULUS - 1) // 4) % MODULUS
  assert_eq!(
    SQRT_M1,
    FieldElement::from(2u8)
      .pow(FieldElement((FieldElement::ZERO - FieldElement::ONE).0.wrapping_div(&U256::from(4u8))))
  );
}

#[test]
fn test_field() {
  ff_group_tests::prime_field::test_prime_field_bits::<_, FieldElement>(&mut rand_core::OsRng);
}
