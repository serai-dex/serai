use core::ops::Div;

use lazy_static::lazy_static;

use zeroize::Zeroize;

use crypto_bigint::{NonZero, U512, U1024};

use crate::field;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Zeroize)]
pub struct FieldElement(pub(crate) U512);

// 2**448 - 2**224 - 1
lazy_static! {
  pub static ref MODULUS: FieldElement = FieldElement(U512::from_be_hex(concat!(
    "00000000000000",
    "00",
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  )));
  static ref WIDE_MODULUS: U1024 = {
    let res = U1024::from((U512::ZERO, MODULUS.0));
    debug_assert_eq!(MODULUS.0.to_le_bytes()[..], res.to_le_bytes()[.. 64]);
    res
  };
}

field!(FieldElement, MODULUS, WIDE_MODULUS);

lazy_static! {
  pub(crate) static ref Q_4: FieldElement = FieldElement(
    MODULUS.0.saturating_add(&U512::ONE).div(NonZero::new(TWO.0.saturating_add(&TWO.0)).unwrap())
  );
}
