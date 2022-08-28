use core::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign};

use lazy_static::lazy_static;

use rand_core::RngCore;

use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable};

use generic_array::{typenum::U57, GenericArray};
use num_traits::{Zero, One};
use num_bigint::{RandBigInt, BigUint};

use crate::{choice, math_op, math};

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct FieldElement(pub(crate) GenericArray::<u8, U57>);

// 2**448 - 2**224 - 1
lazy_static! {
  pub static ref MODULUS: FieldElement = FieldElement(
    hex_literal::hex!(
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffff00"
    ).into()
  );

  static ref MODULUS_INT: BigUint = from_repr_inner(MODULUS.0).unwrap();
}

pub(crate) fn from_repr_inner(bytes: GenericArray<u8, U57>) -> CtOption<BigUint> {
  let res = BigUint::from_bytes_le(bytes.as_ref());
  if bytes == MODULUS.0 {
    return CtOption::new(res, 1.into());
  }
  CtOption::new(res.clone(), choice(res < *MODULUS_INT))
}

pub(crate) fn to_repr_inner(element: BigUint) ->  GenericArray<u8, U57> {
  let mut raw = element.to_bytes_le();
  while raw.len() < 57 {
    raw.push(0);
  }

  let mut repr = GenericArray::<u8, U57>::default();
  repr.copy_from_slice(&raw[.. 57]);
  repr
}

impl ConstantTimeEq for FieldElement {
  fn ct_eq(&self, other: &Self) -> Choice {
    choice(self.0 == other.0)
  }
}

impl ConditionallySelectable for FieldElement {
  fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
    if choice.into() { *b } else { *a }
  }
}

math!(
  FieldElement,
  FieldElement,
  |x, y| to_repr_inner(&(from_repr_inner(x).unwrap() + from_repr_inner(y).unwrap()) % &*MODULUS_INT),
  |x, y| to_repr_inner(&((&from_repr_inner(x).unwrap() + &*MODULUS_INT) - from_repr_inner(y).unwrap()) % &*MODULUS_INT),
  |x, y| to_repr_inner(&(from_repr_inner(x).unwrap() * from_repr_inner(y).unwrap()) % &*MODULUS_INT)
);

impl From<u8> for FieldElement {
  fn from(x: u8) -> FieldElement {
    FieldElement(to_repr_inner(BigUint::from(x)))
  }
}
impl From<u16> for FieldElement {
  fn from(x: u16) -> FieldElement {
    FieldElement(to_repr_inner(BigUint::from(x)))
  }
}
impl From<u32> for FieldElement {
  fn from(x: u32) -> FieldElement {
    FieldElement(to_repr_inner(BigUint::from(x)))
  }
}
impl From<u64> for FieldElement {
  fn from(x: u64) -> FieldElement {
    FieldElement(to_repr_inner(BigUint::from(x)))
  }
}

lazy_static! {
  pub(crate) static ref ZERO: FieldElement = FieldElement(to_repr_inner(BigUint::zero()));
  pub(crate) static ref ONE: FieldElement = FieldElement(to_repr_inner(BigUint::one()));
  pub(crate) static ref TWO: FieldElement = FieldElement(to_repr_inner(BigUint::one() + BigUint::one()));
  pub(crate) static ref Q_4: FieldElement = FieldElement(to_repr_inner((&*MODULUS_INT + &BigUint::one()) / BigUint::from(4u8)));
}

impl FieldElement {
  pub fn pow(&self, other: FieldElement) -> FieldElement {
    FieldElement(to_repr_inner(from_repr_inner(self.0).unwrap().modpow(&from_repr_inner(other.0).unwrap(), &MODULUS_INT)))
  }
}

pub(crate) fn random(mut rng: impl RngCore) -> FieldElement {
  let mut res = rng.gen_biguint(448);
  while res > *MODULUS_INT {
    res = rng.gen_biguint(448);
  }
  FieldElement(to_repr_inner(res))
}

pub(crate) fn from_repr(bytes: GenericArray<u8, U57>) -> CtOption<FieldElement> {
  let opt = Option::from(from_repr_inner(bytes)).map(|x| FieldElement(to_repr_inner(x)));
  CtOption::new(opt.unwrap_or(*ZERO), choice(opt.is_some()))
}

pub(crate) fn to_repr(element: &FieldElement) -> GenericArray<u8, U57> {
  element.0
}
