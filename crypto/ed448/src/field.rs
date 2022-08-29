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

field!(FieldElement, MODULUS, WIDE_MODULUS, 448);

lazy_static! {
  pub(crate) static ref Q_4: FieldElement = FieldElement(
    MODULUS.0.saturating_add(&U512::ONE).div(NonZero::new(TWO.0.saturating_add(&TWO.0)).unwrap())
  );
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
