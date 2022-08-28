use core::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign, Div};

use lazy_static::lazy_static;

use rand_core::RngCore;

use zeroize::Zeroize;
use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable};

use generic_array::{typenum::U57, GenericArray};
use crypto_bigint::{Encoding, NonZero, U512, U1024};

use ff::PrimeFieldBits;

use dalek_ff_group::{constant_time, from_wrapper, from_uint};
use crate::{choice, math_op, math};

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Zeroize)]
pub struct FieldElement(pub(crate) U512);

// 2**448 - 2**224 - 1
lazy_static! {
  pub static ref MODULUS: FieldElement = FieldElement(
    U512::from_be_hex(
      "0000000000000000fffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
  );
}

constant_time!(FieldElement, U512);
math!(
  FieldElement,
  FieldElement,
  |x, y| U512::add_mod(&x, &y, &MODULUS.0),
  |x, y| U512::sub_mod(&x, &y, &MODULUS.0),
  |x, y| {
    #[allow(non_snake_case)]
    let WIDE_MODULUS: U1024 = U1024::from((U512::ZERO, MODULUS.0));
    debug_assert_eq!(MODULUS.0.to_le_bytes()[..], WIDE_MODULUS.to_le_bytes()[.. 64]);

    let wide = U512::mul_wide(&x, &y);
    U512::from_le_slice(
      &U1024::from((wide.1, wide.0)).reduce(&WIDE_MODULUS).unwrap().to_le_bytes()[.. 64],
    )
  }
);
from_uint!(FieldElement, U512);

lazy_static! {
  pub(crate) static ref ZERO: FieldElement = FieldElement(U512::ZERO);
  pub(crate) static ref ONE: FieldElement = FieldElement(U512::ONE);
  pub(crate) static ref TWO: FieldElement = FieldElement(U512::ONE.saturating_add(&U512::ONE));
  pub(crate) static ref Q_4: FieldElement = FieldElement(
    MODULUS.0.saturating_add(&U512::ONE).div(NonZero::new(TWO.0.saturating_add(&TWO.0)).unwrap())
  );
}

impl FieldElement {
  pub fn pow(&self, other: FieldElement) -> FieldElement {
    let mut res = *ONE;
    let mut m = *self;
    for bit in other.to_le_bits() {
      res *= FieldElement::conditional_select(&ONE, &m, choice(bit));
      m *= m;
    }
    res
  }
}

pub(crate) fn random(mut rng: impl RngCore) -> FieldElement {
  let mut bytes = [0; 128];
  rng.fill_bytes(&mut bytes);

  #[allow(non_snake_case)]
  let WIDE_MODULUS: U1024 = U1024::from((U512::ZERO, MODULUS.0));
  debug_assert_eq!(MODULUS.0.to_le_bytes()[..], WIDE_MODULUS.to_le_bytes()[.. 64]);

  FieldElement(U512::from_le_slice(
    &U1024::from_be_bytes(bytes).reduce(&WIDE_MODULUS).unwrap().to_le_bytes()[.. 64],
  ))
}

pub(crate) fn from_repr(bytes: GenericArray<u8, U57>) -> CtOption<FieldElement> {
  let res = FieldElement(U512::from_le_slice(&[bytes.as_ref(), [0; 7].as_ref()].concat()));
  CtOption::new(res, res.0.add_mod(&U512::ZERO, &MODULUS.0).ct_eq(&res.0))
}

pub(crate) fn to_repr(element: &FieldElement) ->  GenericArray<u8, U57> {
  let mut repr = GenericArray::<u8, U57>::default();
  repr.copy_from_slice(&element.0.to_le_bytes()[.. 57]);
  repr
}
