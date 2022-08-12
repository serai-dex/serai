use core::ops::{Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign};

use rand_core::RngCore;

use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable};

use crypto_bigint::{Encoding, U256, U512};

use ff::{Field, PrimeField, FieldBits, PrimeFieldBits};

use crate::{choice, constant_time, math_op, math, from_wrapper, from_uint};

const FIELD_MODULUS: U256 =
  U256::from_be_hex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed");

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct FieldElement(U256);

pub const EDWARDS_D: FieldElement = FieldElement(U256::from_be_hex(
  "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
));

pub const SQRT_M1: FieldElement = FieldElement(U256::from_be_hex(
  "2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0",
));

constant_time!(FieldElement, U256);
math!(
  FieldElement,
  FieldElement,
  |x, y| U256::add_mod(&x, &y, &FIELD_MODULUS),
  |x, y| U256::sub_mod(&x, &y, &FIELD_MODULUS),
  |x, y| {
    #[allow(non_snake_case)]
    let WIDE_MODULUS: U512 = U512::from((U256::ZERO, FIELD_MODULUS));
    debug_assert_eq!(FIELD_MODULUS.to_le_bytes()[..], WIDE_MODULUS.to_le_bytes()[.. 32]);

    let wide = U256::mul_wide(&x, &y);
    U256::from_le_slice(
      &U512::from((wide.1, wide.0)).reduce(&WIDE_MODULUS).unwrap().to_le_bytes()[.. 32],
    )
  }
);
from_uint!(FieldElement, U256);

impl Neg for FieldElement {
  type Output = Self;
  fn neg(self) -> Self::Output {
    Self(self.0.neg_mod(&FIELD_MODULUS))
  }
}

impl Field for FieldElement {
  fn random(mut rng: impl RngCore) -> Self {
    let mut bytes = [0; 64];
    rng.fill_bytes(&mut bytes);

    #[allow(non_snake_case)]
    let WIDE_MODULUS: U512 = U512::from((U256::ZERO, FIELD_MODULUS));
    debug_assert_eq!(FIELD_MODULUS.to_le_bytes()[..], WIDE_MODULUS.to_le_bytes()[.. 32]);

    FieldElement(U256::from_le_slice(
      &U512::from_be_bytes(bytes).reduce(&WIDE_MODULUS).unwrap().to_le_bytes()[.. 32],
    ))
  }

  fn zero() -> Self {
    Self(U256::ZERO)
  }
  fn one() -> Self {
    Self(U256::ONE)
  }
  fn square(&self) -> Self {
    *self * self
  }
  fn double(&self) -> Self {
    *self + self
  }

  fn invert(&self) -> CtOption<Self> {
    CtOption::new(self.pow(-FieldElement(U256::from(2u64))), !self.is_zero())
  }

  fn sqrt(&self) -> CtOption<Self> {
    let c1 = SQRT_M1;
    let c2 = FIELD_MODULUS.saturating_add(&U256::from(3u8)).checked_div(&U256::from(8u8)).unwrap();

    let tv1 = self.pow(FieldElement(c2));
    let tv2 = tv1 * c1;
    let res = Self::conditional_select(&tv2, &tv1, tv1.square().ct_eq(self));
    debug_assert_eq!(res * res, *self);
    CtOption::new(Self::conditional_select(&tv2, &tv1, tv1.square().ct_eq(self)), 1.into())
  }

  fn is_zero(&self) -> Choice {
    self.0.ct_eq(&U256::ZERO)
  }
  fn cube(&self) -> Self {
    *self * self * self
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
    CtOption::new(res, res.0.add_mod(&U256::ZERO, &FIELD_MODULUS).ct_eq(&res.0))
  }
  fn to_repr(&self) -> [u8; 32] {
    self.0.to_le_bytes()
  }

  const S: u32 = 2;
  fn is_odd(&self) -> Choice {
    unimplemented!()
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
    let mut res = FieldElement(U256::ONE);
    let mut m = *self;
    for bit in other.to_le_bits() {
      res *= FieldElement::conditional_select(&FieldElement(U256::ONE), &m, choice(bit));
      m *= m;
    }
    res
  }
}

#[test]
fn test_edwards_d() {
  let a = -FieldElement(U256::from_u32(121665));
  let b = FieldElement(U256::from_u32(121666));

  assert_eq!(EDWARDS_D, a * b.invert().unwrap());
}

#[test]
fn test_mul() {
  assert_eq!(FieldElement(FIELD_MODULUS) * FieldElement::one(), FieldElement::zero());
  assert_eq!(FieldElement(FIELD_MODULUS) * FieldElement::one().double(), FieldElement::zero());
  assert_eq!(SQRT_M1.square(), -FieldElement::one());
}
