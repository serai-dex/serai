use core::ops::Neg;

use rand_core::RngCore;

use subtle::{Choice, CtOption, ConstantTimeEq};

use generic_array::{typenum::U57, GenericArray};

use ff::{Field, PrimeField, FieldBits, PrimeFieldBits};

pub use crate::hazmat::backend::field::*;

impl Neg for FieldElement {
  type Output = FieldElement;
  fn neg(self) -> FieldElement {
    *MODULUS - self
  }
}

impl<'a> Neg for &'a FieldElement {
  type Output = FieldElement;
  fn neg(self) -> Self::Output {
    (*self).neg()
  }
}

impl Field for FieldElement {
  fn random(rng: impl RngCore) -> Self {
    random(rng)
  }

  fn zero() -> Self {
    *ZERO
  }
  fn one() -> Self {
    *ONE
  }
  fn square(&self) -> Self {
    *self * self
  }
  fn double(&self) -> Self {
    *self + self
  }

  fn invert(&self) -> CtOption<Self> {
    CtOption::new(self.pow(-*TWO), !self.is_zero())
  }

  fn sqrt(&self) -> CtOption<Self> {
    unimplemented!()
  }

  fn is_zero(&self) -> Choice {
    self.ct_eq(&ZERO)
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
    from_repr(bytes)
  }
  fn to_repr(&self) -> Self::Repr {
    to_repr(self)
  }

  const S: u32 = 1;
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
  type ReprBits = [u8; 56];

  fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
    let mut repr = [0; 56];
    repr.copy_from_slice(&self.to_repr()[.. 56]);
    repr.into()
  }

  fn char_le_bits() -> FieldBits<Self::ReprBits> {
    MODULUS.to_le_bits()
  }
}

#[test]
fn repr() {
  assert_eq!(FieldElement::from_repr(FieldElement::one().to_repr()).unwrap(), FieldElement::one());
}

#[test]
fn one_two() {
  assert_eq!(FieldElement::one() * FieldElement::one().double(), FieldElement::from(2u8));
  assert_eq!(
    FieldElement::from_repr(FieldElement::from(2u8).to_repr()).unwrap(),
    FieldElement::from(2u8)
  );
}

#[test]
fn pow() {
  assert_eq!(FieldElement::one().pow(FieldElement::one()), FieldElement::one());
  let two = FieldElement::one().double();
  assert_eq!(two.pow(two), two.double());

  let three = two + FieldElement::one();
  assert_eq!(three.pow(three), three * three * three);
}

#[test]
fn invert() {
  assert_eq!(FieldElement::one().invert().unwrap(), FieldElement::one());
}
