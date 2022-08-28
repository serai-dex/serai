use core::ops::{Add, AddAssign, Sub, SubAssign, Mul, MulAssign};

use lazy_static::lazy_static;

use rand_core::RngCore;

use subtle::{Choice, CtOption, ConstantTimeEq, ConditionallySelectable};

use generic_array::{typenum::U57, GenericArray};
use crypto_bigint::{Encoding, U512, U1024};

use ff::PrimeFieldBits;

use dalek_ff_group::{constant_time, from_wrapper, from_uint};
use crate::{choice, math_op, math};

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Scalar(pub(crate) U512);

// 2**446 - 13818066809895115352007386748515426880336692474882178609894547503885
lazy_static! {
  pub static ref MODULUS: Scalar = Scalar(
    U512::from_be_hex(
      "00000000000000003fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"
    )
  );
}

constant_time!(Scalar, U512);
math!(
  Scalar,
  Scalar,
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
from_uint!(Scalar, U512);

lazy_static! {
  pub(crate) static ref ZERO: Scalar = Scalar(U512::ZERO);
  pub(crate) static ref ONE: Scalar = Scalar(U512::ONE);
  pub(crate) static ref TWO: Scalar = Scalar(U512::ONE.saturating_add(&U512::ONE));
}

impl Scalar {
  pub fn pow(&self, other: Scalar) -> Scalar {
    let mut res = *ONE;
    let mut m = *self;
    for bit in other.to_le_bits() {
      res *= Scalar::conditional_select(&ONE, &m, choice(bit));
      m *= m;
    }
    res
  }
}

pub(crate) fn random(mut rng: impl RngCore) -> Scalar {
  let mut bytes = [0; 128];
  rng.fill_bytes(&mut bytes);

  #[allow(non_snake_case)]
  let WIDE_MODULUS: U1024 = U1024::from((U512::ZERO, MODULUS.0));
  debug_assert_eq!(MODULUS.0.to_le_bytes()[..], WIDE_MODULUS.to_le_bytes()[.. 64]);

  Scalar(U512::from_le_slice(
    &U1024::from_be_bytes(bytes).reduce(&WIDE_MODULUS).unwrap().to_le_bytes()[.. 64],
  ))
}

pub(crate) fn from_repr(bytes: GenericArray<u8, U57>) -> CtOption<Scalar> {
  let res = Scalar(U512::from_le_slice(&[bytes.as_ref(), [0; 7].as_ref()].concat()));
  CtOption::new(res, res.0.add_mod(&U512::ZERO, &MODULUS.0).ct_eq(&res.0))
}

pub(crate) fn to_repr(scalar: &Scalar) -> GenericArray<u8, U57> {
  let mut repr = GenericArray::<u8, U57>::default();
  repr.copy_from_slice(&scalar.0.to_le_bytes()[.. 57]);
  repr
}
