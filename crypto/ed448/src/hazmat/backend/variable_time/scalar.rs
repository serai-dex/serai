use core::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign};

use lazy_static::lazy_static;

use rand_core::RngCore;

use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable};

use generic_array::{typenum::U57, GenericArray};

use num_traits::identities::{Zero, One};
use num_bigint::{RandBigInt, BigUint};

use crate::{choice, math_op, math};

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Scalar(pub(crate) GenericArray::<u8, U57>);

// 2**446 - 13818066809895115352007386748515426880336692474882178609894547503885
lazy_static! {
  pub static ref MODULUS: Scalar = Scalar(
    hex_literal::hex!(
      "f34458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffffffffffffffffffffffffffffffffffffffffffffffffff3f00"
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

impl ConstantTimeEq for Scalar {
  fn ct_eq(&self, other: &Self) -> Choice {
    choice(self.0 == other.0)
  }
}

impl ConditionallySelectable for Scalar {
  fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
    if choice.into() { *b } else { *a }
  }
}

math!(
  Scalar,
  Scalar,
  |x, y| to_repr_inner(&(from_repr_inner(x).unwrap() + from_repr_inner(y).unwrap()) % &*MODULUS_INT),
  |x, y| to_repr_inner(&((&from_repr_inner(x).unwrap() + &*MODULUS_INT) - from_repr_inner(y).unwrap()) % &*MODULUS_INT),
  |x, y| to_repr_inner(&(from_repr_inner(x).unwrap() * from_repr_inner(y).unwrap()) % &*MODULUS_INT)
);

impl From<u8> for Scalar {
  fn from(x: u8) -> Scalar {
    Scalar(to_repr_inner(BigUint::from(x)))
  }
}
impl From<u16> for Scalar {
  fn from(x: u16) -> Scalar {
    Scalar(to_repr_inner(BigUint::from(x)))
  }
}
impl From<u32> for Scalar {
  fn from(x: u32) -> Scalar {
    Scalar(to_repr_inner(BigUint::from(x)))
  }
}
impl From<u64> for Scalar {
  fn from(x: u64) -> Scalar {
    Scalar(to_repr_inner(BigUint::from(x)))
  }
}

lazy_static! {
  pub(crate) static ref ZERO: Scalar = Scalar(to_repr_inner(BigUint::zero()));
  pub(crate) static ref ONE: Scalar = Scalar(to_repr_inner(BigUint::one()));
  pub(crate) static ref TWO: Scalar = Scalar(to_repr_inner(BigUint::one() + BigUint::one()));
}

impl Scalar {
  pub fn pow(&self, other: Scalar) -> Scalar {
    Scalar(to_repr_inner(from_repr_inner(self.0).unwrap().modpow(&from_repr_inner(other.0).unwrap(), &MODULUS_INT)))
  }
}

pub(crate) fn random(mut rng: impl RngCore) -> Scalar {
  let mut res = rng.gen_biguint(446);
  while res > *MODULUS_INT {
    res = rng.gen_biguint(446);
  }
  Scalar(to_repr_inner(res))
}

pub(crate) fn from_repr(bytes: GenericArray<u8, U57>) -> CtOption<Scalar> {
  let opt = Option::from(from_repr_inner(bytes)).map(|x| Scalar(to_repr_inner(x)));
  CtOption::new(opt.unwrap_or(*ZERO), choice(opt.is_some()))
}

pub(crate) fn to_repr(element: &Scalar) -> GenericArray<u8, U57> {
  element.0
}
