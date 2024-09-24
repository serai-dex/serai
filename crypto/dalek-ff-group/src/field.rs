use core::{
  ops::{Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign},
  iter::{Sum, Product},
};

use zeroize::Zeroize;
use rand_core::RngCore;

use subtle::{
  Choice, CtOption, ConstantTimeEq, ConstantTimeLess, ConditionallyNegatable,
  ConditionallySelectable,
};

use crypto_bigint::{
  Integer, NonZero, Encoding, U256, U512,
  modular::constant_mod::{ResidueParams, Residue},
  impl_modulus,
};

use group::ff::{Field, PrimeField, FieldBits, PrimeFieldBits};

use crate::{u8_from_bool, constant_time, math_op, math};

// 2 ** 255 - 19
// Uses saturating_sub because checked_sub isn't available at compile time
const MODULUS: U256 = U256::from_u8(1).shl_vartime(255).saturating_sub(&U256::from_u8(19));
const WIDE_MODULUS: U512 = U256::ZERO.concat(&MODULUS);

impl_modulus!(
  FieldModulus,
  U256,
  // 2 ** 255 - 19
  "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
);
type ResidueType = Residue<FieldModulus, { FieldModulus::LIMBS }>;

/// A constant-time implementation of the Ed25519 field.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Zeroize)]
pub struct FieldElement(ResidueType);

// Square root of -1.
// Formula from RFC-8032 (modp_sqrt_m1/sqrt8k5 z)
// 2 ** ((MODULUS - 1) // 4) % MODULUS
const SQRT_M1: FieldElement = FieldElement(
  ResidueType::new(&U256::from_u8(2))
    .pow(&MODULUS.saturating_sub(&U256::ONE).wrapping_div(&U256::from_u8(4))),
);

// Constant useful in calculating square roots (RFC-8032 sqrt8k5's exponent used to calculate y)
const MOD_3_8: FieldElement = FieldElement(ResidueType::new(
  &MODULUS.saturating_add(&U256::from_u8(3)).wrapping_div(&U256::from_u8(8)),
));

// Constant useful in sqrt_ratio_i (sqrt(u / v))
const MOD_5_8: FieldElement = FieldElement(ResidueType::sub(&MOD_3_8.0, &ResidueType::ONE));

fn reduce(x: U512) -> ResidueType {
  ResidueType::new(&U256::from_le_slice(
    &x.rem(&NonZero::new(WIDE_MODULUS).unwrap()).to_le_bytes()[.. 32],
  ))
}

constant_time!(FieldElement, ResidueType);
math!(
  FieldElement,
  FieldElement,
  |x: ResidueType, y: ResidueType| x.add(&y),
  |x: ResidueType, y: ResidueType| x.sub(&y),
  |x: ResidueType, y: ResidueType| x.mul(&y)
);

macro_rules! from_wrapper {
  ($uint: ident) => {
    impl From<$uint> for FieldElement {
      fn from(a: $uint) -> FieldElement {
        Self(ResidueType::new(&U256::from(a)))
      }
    }
  };
}

from_wrapper!(u8);
from_wrapper!(u16);
from_wrapper!(u32);
from_wrapper!(u64);
from_wrapper!(u128);

impl Neg for FieldElement {
  type Output = Self;
  fn neg(self) -> Self::Output {
    Self(self.0.neg())
  }
}

impl<'a> Neg for &'a FieldElement {
  type Output = FieldElement;
  fn neg(self) -> Self::Output {
    (*self).neg()
  }
}

impl Field for FieldElement {
  const ZERO: Self = Self(ResidueType::ZERO);
  const ONE: Self = Self(ResidueType::ONE);

  fn random(mut rng: impl RngCore) -> Self {
    let mut bytes = [0; 64];
    rng.fill_bytes(&mut bytes);
    FieldElement(reduce(U512::from_le_bytes(bytes)))
  }

  fn square(&self) -> Self {
    FieldElement(self.0.square())
  }
  fn double(&self) -> Self {
    FieldElement(self.0.add(&self.0))
  }

  fn invert(&self) -> CtOption<Self> {
    const NEG_2: FieldElement =
      FieldElement(ResidueType::new(&MODULUS.saturating_sub(&U256::from_u8(2))));
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

  const TWO_INV: Self = FieldElement(ResidueType::new(&U256::from_u8(2)).invert().0);

  // This was calculated with the method from the ff crate docs
  // SageMath GF(modulus).primitive_element()
  const MULTIPLICATIVE_GENERATOR: Self = Self(ResidueType::new(&U256::from_u8(2)));
  // This was set per the specification in the ff crate docs
  // The number of leading zero bits in the little-endian bit representation of (modulus - 1)
  const S: u32 = 2;

  // This was calculated via the formula from the ff crate docs
  // Self::MULTIPLICATIVE_GENERATOR ** ((modulus - 1) >> Self::S)
  const ROOT_OF_UNITY: Self = FieldElement(ResidueType::new(&U256::from_be_hex(
    "2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0",
  )));
  // Self::ROOT_OF_UNITY.invert()
  const ROOT_OF_UNITY_INV: Self = FieldElement(Self::ROOT_OF_UNITY.0.invert().0);

  // This was calculated via the formula from the ff crate docs
  // Self::MULTIPLICATIVE_GENERATOR ** (2 ** Self::S)
  const DELTA: Self = FieldElement(ResidueType::new(&U256::from_be_hex(
    "0000000000000000000000000000000000000000000000000000000000000010",
  )));

  fn from_repr(bytes: [u8; 32]) -> CtOption<Self> {
    let res = U256::from_le_bytes(bytes);
    CtOption::new(Self(ResidueType::new(&res)), res.ct_lt(&MODULUS))
  }
  fn to_repr(&self) -> [u8; 32] {
    self.0.retrieve().to_le_bytes()
  }

  fn is_odd(&self) -> Choice {
    self.0.retrieve().is_odd()
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
    FieldElement(reduce(U512::from(value.mul_wide(&value))))
  }

  /// Perform an exponentiation.
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
      let mut bit = u8_from_bool(&mut bit);
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
    iter.copied().sum()
  }
}

impl Product<FieldElement> for FieldElement {
  fn product<I: Iterator<Item = FieldElement>>(iter: I) -> FieldElement {
    let mut res = FieldElement::ONE;
    for item in iter {
      res *= item;
    }
    res
  }
}

impl<'a> Product<&'a FieldElement> for FieldElement {
  fn product<I: Iterator<Item = &'a FieldElement>>(iter: I) -> FieldElement {
    iter.copied().product()
  }
}

#[test]
fn test_wide_modulus() {
  let mut wide = [0; 64];
  wide[.. 32].copy_from_slice(&MODULUS.to_le_bytes());
  assert_eq!(wide, WIDE_MODULUS.to_le_bytes());
}

#[test]
fn test_sqrt_m1() {
  // Test equivalence against the known constant value
  const SQRT_M1_MAGIC: U256 =
    U256::from_be_hex("2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0");
  assert_eq!(SQRT_M1.0.retrieve(), SQRT_M1_MAGIC);

  // Also test equivalence against the result of the formula from RFC-8032 (modp_sqrt_m1/sqrt8k5 z)
  // 2 ** ((MODULUS - 1) // 4) % MODULUS
  assert_eq!(
    SQRT_M1,
    FieldElement::from(2u8).pow(FieldElement(ResidueType::new(
      &(FieldElement::ZERO - FieldElement::ONE).0.retrieve().wrapping_div(&U256::from(4u8))
    )))
  );
}

#[test]
fn test_field() {
  ff_group_tests::prime_field::test_prime_field_bits::<_, FieldElement>(&mut rand_core::OsRng);
}
