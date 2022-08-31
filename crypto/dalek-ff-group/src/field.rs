use core::ops::{Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign};

use rand_core::RngCore;

use subtle::{
  Choice, CtOption, ConstantTimeEq, ConstantTimeLess, ConditionallyNegatable,
  ConditionallySelectable,
};

use crypto_bigint::{Integer, Encoding, U256, U512};

use ff::{Field, PrimeField, FieldBits, PrimeFieldBits};

use crate::{constant_time, math, from_uint};

const FIELD_MODULUS: U256 =
  U256::from_be_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");

const WIDE_MODULUS: U512 = U512::from_be_hex(concat!(
  "0000000000000000000000000000000000000000000000000000000000000000",
  "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
));

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct FieldElement(U256);

pub const MOD_3_8: FieldElement =
  FieldElement(FIELD_MODULUS.saturating_add(&U256::from_u8(3)).wrapping_div(&U256::from_u8(8)));

pub const MOD_5_8: FieldElement = FieldElement(MOD_3_8.0.saturating_sub(&U256::ONE));

pub const EDWARDS_D: FieldElement = FieldElement(U256::from_be_hex(
  "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
));

pub const SQRT_M1: FieldElement = FieldElement(U256::from_be_hex(
  "2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0",
));

fn reduce(x: U512) -> U256 {
  U256::from_le_slice(&x.reduce(&WIDE_MODULUS).unwrap().to_le_bytes()[.. 32])
}

constant_time!(FieldElement, U256);
math!(
  FieldElement,
  FieldElement,
  |x, y| U256::add_mod(&x, &y, &FIELD_MODULUS),
  |x, y| U256::sub_mod(&x, &y, &FIELD_MODULUS),
  |x, y| {
    let wide = U256::mul_wide(&x, &y);
    reduce(U512::from((wide.1, wide.0)))
  }
);
from_uint!(FieldElement, U256);

impl Neg for FieldElement {
  type Output = Self;
  fn neg(self) -> Self::Output {
    Self(self.0.neg_mod(&FIELD_MODULUS))
  }
}

impl<'a> Neg for &'a FieldElement {
  type Output = FieldElement;
  fn neg(self) -> Self::Output {
    (*self).neg()
  }
}

impl Field for FieldElement {
  fn random(mut rng: impl RngCore) -> Self {
    let mut bytes = [0; 64];
    rng.fill_bytes(&mut bytes);
    FieldElement(reduce(U512::from_le_bytes(bytes)))
  }

  fn zero() -> Self {
    Self(U256::ZERO)
  }
  fn one() -> Self {
    Self(U256::ONE)
  }
  fn square(&self) -> Self {
    FieldElement(reduce(self.0.square()))
  }
  fn double(&self) -> Self {
    FieldElement((self.0 << 1).reduce(&FIELD_MODULUS).unwrap())
  }

  fn invert(&self) -> CtOption<Self> {
    const NEG_2: FieldElement = FieldElement(FIELD_MODULUS.saturating_sub(&U256::from_u8(2)));
    CtOption::new(self.pow(NEG_2), !self.is_zero())
  }

  fn sqrt(&self) -> CtOption<Self> {
    let tv1 = self.pow(MOD_3_8);
    let tv2 = tv1 * SQRT_M1;
    CtOption::new(Self::conditional_select(&tv2, &tv1, tv1.square().ct_eq(self)), 1.into())
  }

  fn is_zero(&self) -> Choice {
    self.0.ct_eq(&U256::ZERO)
  }
  fn cube(&self) -> Self {
    self.square() * self
  }
  fn pow_vartime<S: AsRef<[u64]>>(&self, _exp: S) -> Self {
    unimplemented!()
  }
}

impl PrimeField for FieldElement {
  type Repr = [u8; 32];
  const NUM_BITS: u32 = 255;
  const CAPACITY: u32 = 254;
  fn from_repr(bytes: [u8; 32]) -> CtOption<Self> {
    let res = Self(U256::from_le_bytes(bytes));
    CtOption::new(res, res.0.ct_lt(&FIELD_MODULUS))
  }
  fn to_repr(&self) -> [u8; 32] {
    self.0.to_le_bytes()
  }

  const S: u32 = 2;
  fn is_odd(&self) -> Choice {
    self.0.is_odd()
  }
  fn multiplicative_generator() -> Self {
    2u64.into()
  }
  fn root_of_unity() -> Self {
    FieldElement(U256::from_be_hex(
      "2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0",
    ))
  }
}

impl PrimeFieldBits for FieldElement {
  type ReprBits = [u8; 32];

  fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
    self.to_repr().into()
  }

  fn char_le_bits() -> FieldBits<Self::ReprBits> {
    FIELD_MODULUS.to_le_bytes().into()
  }
}

impl FieldElement {
  pub fn from_square(value: [u8; 32]) -> FieldElement {
    let value = U256::from_le_bytes(value);
    FieldElement(value) * FieldElement(value)
  }

  pub fn pow(&self, other: FieldElement) -> FieldElement {
    let mut table = [FieldElement(U256::ONE); 16];
    table[1] = *self;
    for i in 2 .. 16 {
      table[i] = table[i - 1] * self;
    }

    let mut res = FieldElement(U256::ONE);
    let mut bits = 0;
    for (i, bit) in other.to_le_bits().iter().rev().enumerate() {
      bits <<= 1;
      let bit = *bit as u8;
      assert_eq!(bit | 1, 1);
      bits |= bit;

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

  pub fn sqrt_ratio_i(u: FieldElement, v: FieldElement) -> (Choice, FieldElement) {
    let i = SQRT_M1;

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

#[test]
fn test_conditional_negate() {
  let one = FieldElement::one();
  let true_choice = 1.into();
  let false_choice = 0.into();

  let mut var = one;

  var.conditional_negate(false_choice);
  assert_eq!(var, FieldElement::one());

  var.conditional_negate(true_choice);
  assert_eq!(var, -FieldElement::one());

  var.conditional_negate(false_choice);
  assert_eq!(var, -FieldElement::one());
}

#[test]
fn test_edwards_d() {
  // TODO: Generate the constant with this when const fn mul_mod is available, removing the need
  // for this test
  let a = -FieldElement::from(121665u32);
  let b = FieldElement::from(121666u32);
  assert_eq!(EDWARDS_D, a * b.invert().unwrap());
}

#[test]
fn test_is_odd() {
  assert_eq!(0, FieldElement::zero().is_odd().unwrap_u8());
  assert_eq!(1, FieldElement::one().is_odd().unwrap_u8());
  assert_eq!(0, FieldElement::one().double().is_odd().unwrap_u8());

  // 0 is even, yet the modulus is odd
  // -1 moves to the even value before the modulus
  assert_eq!(0, (-FieldElement::one()).is_odd().unwrap_u8());
  assert_eq!(1, (-FieldElement::one().double()).is_odd().unwrap_u8());
}

#[test]
fn test_mul() {
  assert_eq!(FieldElement(FIELD_MODULUS) * FieldElement::one(), FieldElement::zero());
  assert_eq!(FieldElement(FIELD_MODULUS) * FieldElement::one().double(), FieldElement::zero());
  assert_eq!(SQRT_M1.square(), -FieldElement::one());
}

#[test]
fn test_sqrt_ratio_i() {
  let zero = FieldElement::zero();
  let one = FieldElement::one();
  let two = one + one;
  let three = two + one;

  let (choice, sqrt) = FieldElement::sqrt_ratio_i(zero, zero);
  assert_eq!(sqrt, zero);
  assert_eq!(sqrt.is_odd().unwrap_u8(), 0);
  assert_eq!(choice.unwrap_u8(), 1);

  let (choice, sqrt) = FieldElement::sqrt_ratio_i(one, zero);
  assert_eq!(sqrt, zero);
  assert_eq!(sqrt.is_odd().unwrap_u8(), 0);
  assert_eq!(choice.unwrap_u8(), 0);

  let (choice, sqrt) = FieldElement::sqrt_ratio_i(two, one);
  assert_eq!(sqrt.square(), two * SQRT_M1);
  assert_eq!(sqrt.is_odd().unwrap_u8(), 0);
  assert_eq!(choice.unwrap_u8(), 0);

  let (choice, sqrt) = FieldElement::sqrt_ratio_i(three, one);
  assert_eq!(sqrt.square(), three);
  assert_eq!(sqrt.is_odd().unwrap_u8(), 0);
  assert_eq!(choice.unwrap_u8(), 1);

  let (choice, sqrt) = FieldElement::sqrt_ratio_i(one, three);
  assert_eq!(sqrt.square() * three, one);
  assert_eq!(sqrt.is_odd().unwrap_u8(), 0);
  assert_eq!(choice.unwrap_u8(), 1);
}
