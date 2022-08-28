use core::ops::Neg;

use rand_core::RngCore;

use subtle::{Choice, CtOption, ConstantTimeEq};

use generic_array::{typenum::U57, GenericArray};

use ff::{Field, PrimeField, FieldBits, PrimeFieldBits};

pub use crate::hazmat::backend::scalar::*;

impl Neg for Scalar {
  type Output = Scalar;
  fn neg(self) -> Self::Output {
    *MODULUS - self
  }
}

impl<'a> Neg for &'a Scalar {
  type Output = Scalar;
  fn neg(self) -> Self::Output {
    (*self).neg()
  }
}

impl Field for Scalar {
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

impl PrimeField for Scalar {
  type Repr = GenericArray<u8, U57>;
  const NUM_BITS: u32 = 456;
  const CAPACITY: u32 = 455;
  fn from_repr(bytes: Self::Repr) -> CtOption<Self> {
    from_repr(bytes)
  }
  fn to_repr(&self) -> Self::Repr {
    to_repr(self)
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

impl PrimeFieldBits for Scalar {
  type ReprBits = [u8; 57];

  fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
    let mut repr = [0; 57];
    repr.copy_from_slice(&self.to_repr());
    repr.into()
  }

  fn char_le_bits() -> FieldBits<Self::ReprBits> {
    MODULUS.to_le_bits()
  }
}
