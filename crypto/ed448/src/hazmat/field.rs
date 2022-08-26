use core::ops::{Add, AddAssign, Sub, SubAssign, Neg, Mul, MulAssign};

use lazy_static::lazy_static;

use rand_core::RngCore;

use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable};

use generic_array::{typenum::U57, GenericArray};
use crypto_bigint::{Encoding, U512, U1024};

use ff::{Field, PrimeField, FieldBits, PrimeFieldBits};

use crate::{choice, constant_time, math_op, math, from_wrapper, from_uint};

// 2**448 - 2**224 - 1
lazy_static! {
  pub static ref MODULUS: U512 = U512::from_be_hex(
    "0000000000000000\
fffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  )
  .into();
}

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct FieldElement(pub(crate) U512);

constant_time!(FieldElement, U512);
math!(
  FieldElement,
  FieldElement,
  |x, y| U512::add_mod(&x, &y, &MODULUS),
  |x, y| U512::sub_mod(&x, &y, &MODULUS),
  |x, y| {
    #[allow(non_snake_case)]
    let WIDE_MODULUS: U1024 = U1024::from((U512::ZERO, *MODULUS));
    let wide = U512::mul_wide(&x, &y);
    U512::from_le_slice(
      &U1024::from((wide.1, wide.0)).reduce(&WIDE_MODULUS).unwrap().to_le_bytes()[.. 64],
    )
  }
);
from_uint!(FieldElement, U512);

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

impl FieldElement {
  pub fn pow(&self, other: FieldElement) -> FieldElement {
    let mut res = FieldElement(U512::ONE);
    let mut m = *self;
    for bit in other.to_le_bits() {
      res *= FieldElement::conditional_select(&FieldElement(U512::ONE), &m, choice(bit));
      m *= m;
    }
    res
  }
}

impl Field for FieldElement {
  fn random(mut rng: impl RngCore) -> Self {
    let mut bytes = [0; 128];
    rng.fill_bytes(&mut bytes);

    #[allow(non_snake_case)]
    let WIDE_MODULUS: U1024 = U1024::from((U512::ZERO, *MODULUS));
    FieldElement(U512::from_le_slice(
      &U1024::from_be_bytes(bytes).reduce(&WIDE_MODULUS).unwrap().to_le_bytes()[.. 64],
    ))
  }

  fn zero() -> Self {
    Self(U512::ZERO)
  }
  fn one() -> Self {
    Self(U512::ONE)
  }
  fn square(&self) -> Self {
    *self * self
  }
  fn double(&self) -> Self {
    *self + self
  }

  fn invert(&self) -> CtOption<Self> {
    CtOption::new(self.pow(-FieldElement(U512::from(2u64))), !self.is_zero())
  }

  fn sqrt(&self) -> CtOption<Self> {
    unimplemented!()
  }

  fn is_zero(&self) -> Choice {
    self.0.ct_eq(&U512::ZERO)
  }
  fn cube(&self) -> Self {
    *self * self * self
  }
  fn pow_vartime<S: AsRef<[u64]>>(&self, _exp: S) -> Self {
    unimplemented!()
  }
}

impl PrimeField for FieldElement {
  type Repr = GenericArray<u8, U57>;
  const NUM_BITS: u32 = 448;
  const CAPACITY: u32 = 447;
  fn from_repr(bytes: Self::Repr) -> CtOption<Self> {
    let res = Self(U512::from_le_slice(&[bytes.as_ref(), [0; 7].as_ref()].concat()));
    CtOption::new(res, res.0.add_mod(&U512::ZERO, &MODULUS).ct_eq(&res.0))
  }
  fn to_repr(&self) -> Self::Repr {
    let mut repr = Self::Repr::default();
    repr.copy_from_slice(&self.0.to_le_bytes()[0 .. 57]);
    repr
  }

  const S: u32 = 0;
  fn is_odd(&self) -> Choice {
    (self.to_repr()[0] & 1).into()
  }
  fn multiplicative_generator() -> Self {
    unimplemented!()
  }
  fn root_of_unity() -> Self {
    unimplemented!()
  }
}

impl PrimeFieldBits for FieldElement {
  type ReprBits = [u8; 57];

  fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
    let mut repr = [0; 57];
    repr.copy_from_slice(&self.to_repr());
    repr.into()
  }

  fn char_le_bits() -> FieldBits<Self::ReprBits> {
    let mut repr = [0; 57];
    repr.copy_from_slice(&MODULUS.to_le_bytes());
    repr.into()
  }
}
