use core::ops::{Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign};

use rand_core::RngCore;

use subtle::{
  Choice, CtOption, ConstantTimeEq, ConstantTimeLess, ConditionallyNegatable,
  ConditionallySelectable,
};

use crypto_bigint::{Integer, Encoding, U256, U512};

use ff::{Field, PrimeField, FieldBits, PrimeFieldBits};

use crate::{constant_time, math, from_uint};

const MODULUS: U256 =
  U256::from_be_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");

const WIDE_MODULUS: U512 = U512::from_be_hex(concat!(
  "0000000000000000000000000000000000000000000000000000000000000000",
  "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
));

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct FieldElement(U256);

pub const MOD_3_8: FieldElement =
  FieldElement(MODULUS.saturating_add(&U256::from_u8(3)).wrapping_div(&U256::from_u8(8)));

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
  |x, y| U256::add_mod(&x, &y, &MODULUS),
  |x, y| U256::sub_mod(&x, &y, &MODULUS),
  |x, y| {
    let wide = U256::mul_wide(&x, &y);
    reduce(U512::from((wide.1, wide.0)))
  }
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
    FieldElement((self.0 << 1).reduce(&MODULUS).unwrap())
  }

  fn invert(&self) -> CtOption<Self> {
    const NEG_2: FieldElement = FieldElement(MODULUS.saturating_sub(&U256::from_u8(2)));
    CtOption::new(self.pow(NEG_2), !self.is_zero())
  }

  fn sqrt(&self) -> CtOption<Self> {
    let tv1 = self.pow(MOD_3_8);
    let tv2 = tv1 * SQRT_M1;
    let candidate = Self::conditional_select(&tv2, &tv1, tv1.square().ct_eq(self));
    CtOption::new(candidate, candidate.square().ct_eq(self))
  }

  fn is_zero(&self) -> Choice {
    self.0.ct_eq(&U256::ZERO)
  }

  fn cube(&self) -> Self {
    self.square() * self
  }

  fn pow_vartime<S: AsRef<[u64]>>(&self, exp: S) -> Self {
    let mut sum = Self::one();
    let mut accum = *self;
    for (_, num) in exp.as_ref().iter().enumerate() {
      let mut num = *num;
      for _ in 0 .. 64 {
        if (num & 1) == 1 {
          sum *= accum;
        }
        num >>= 1;
        accum *= accum;
      }
    }
    sum
  }
}

impl PrimeField for FieldElement {
  type Repr = [u8; 32];
  const NUM_BITS: u32 = 255;
  const CAPACITY: u32 = 254;
  fn from_repr(bytes: [u8; 32]) -> CtOption<Self> {
    let res = Self(U256::from_le_bytes(bytes));
    CtOption::new(res, res.0.ct_lt(&MODULUS))
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
    MODULUS.to_le_bytes().into()
  }
}

impl FieldElement {
  pub fn from_square(value: [u8; 32]) -> FieldElement {
    let value = U256::from_le_bytes(value);
    FieldElement(value) * FieldElement(value)
  }

  pub fn pow(&self, other: FieldElement) -> FieldElement {
    let mut table = [FieldElement::one(); 16];
    table[1] = *self;
    for i in 2 .. 16 {
      table[i] = table[i - 1] * self;
    }

    let mut res = FieldElement::one();
    let mut bits = 0;
    for (i, bit) in other.to_le_bits().iter().rev().enumerate() {
      bits <<= 1;
      let bit = u8::from(*bit);
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
fn test_s() {
  // "This is the number of leading zero bits in the little-endian bit representation of
  // `modulus - 1`."
  let mut s = 0;
  for b in (FieldElement::zero() - FieldElement::one()).to_le_bits() {
    if b {
      break;
    }
    s += 1;
  }
  assert_eq!(s, FieldElement::S);
}

#[test]
fn test_root_of_unity() {
  // "It can be calculated by exponentiating `Self::multiplicative_generator` by `t`, where
  // `t = (modulus - 1) >> Self::S`."
  let t = FieldElement::zero() - FieldElement::one();
  let mut bytes = t.to_repr();
  for _ in 0 .. FieldElement::S {
    bytes[0] >>= 1;
    for b in 1 .. 32 {
      // Shift the dropped but down a byte
      bytes[b - 1] |= (bytes[b] & 1) << 7;
      // Shift the byte
      bytes[b] >>= 1;
    }
  }
  let t = FieldElement::from_repr(bytes).unwrap();

  assert_eq!(FieldElement::multiplicative_generator().pow(t), FieldElement::root_of_unity());
  assert_eq!(
    FieldElement::root_of_unity()
      .pow(FieldElement::from(2u64).pow(FieldElement::from(FieldElement::S))),
    FieldElement::one()
  );
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
fn test_sqrt_m1() {
  // TODO: Ideally, tlike EDWARDS_D, this would be calculated undder const. A const pow is just
  // even more unlikely than a const mul...
  let sqrt_m1 = MODULUS.saturating_sub(&U256::from_u8(1)).wrapping_div(&U256::from_u8(4));
  let sqrt_m1 =
    FieldElement::one().double().pow(FieldElement::from_repr(sqrt_m1.to_le_bytes()).unwrap());
  assert_eq!(SQRT_M1, sqrt_m1);
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
  assert_eq!(FieldElement(MODULUS) * FieldElement::one(), FieldElement::zero());
  assert_eq!(FieldElement(MODULUS) * FieldElement::one().double(), FieldElement::zero());
  assert_eq!(SQRT_M1.square(), -FieldElement::one());
}

#[test]
fn test_sqrt() {
  assert_eq!(FieldElement::zero().sqrt().unwrap(), FieldElement::zero());
  assert_eq!(FieldElement::one().sqrt().unwrap(), FieldElement::one());
  for _ in 0 .. 10 {
    let mut elem;
    while {
      elem = FieldElement::random(&mut rand_core::OsRng);
      elem.sqrt().is_none().into()
    } {}
    assert_eq!(elem.sqrt().unwrap().square(), elem);
  }
}

#[test]
fn test_pow() {
  let base = FieldElement::from(0b11100101u64);
  assert_eq!(base.pow(FieldElement::zero()), FieldElement::one());
  assert_eq!(base.pow_vartime(&[]), FieldElement::one());
  assert_eq!(base.pow_vartime(&[0]), FieldElement::one());
  assert_eq!(base.pow_vartime(&[0, 0]), FieldElement::one());

  assert_eq!(base.pow(FieldElement::one()), base);
  assert_eq!(base.pow_vartime(&[1]), base);
  assert_eq!(base.pow_vartime(&[1, 0]), base);

  let one_65 = FieldElement::from(u64::MAX) + FieldElement::one();
  assert_eq!(base.pow_vartime(&[0, 1]), base.pow(one_65));
  assert_eq!(base.pow_vartime(&[1, 1]), base.pow(one_65 + FieldElement::one()));
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
