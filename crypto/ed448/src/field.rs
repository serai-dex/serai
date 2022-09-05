use zeroize::Zeroize;

use crypto_bigint::{U512, U1024};

use crate::field;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Zeroize)]
pub struct FieldElement(pub(crate) U512);

// 2**448 - 2**224 - 1
pub const MODULUS: FieldElement = FieldElement(U512::from_be_hex(concat!(
  "00000000000000",
  "00",
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
)));

const WIDE_MODULUS: U1024 = U1024::from_be_hex(concat!(
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "00000000000000",
  "00",
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
));

pub(crate) const Q_4: FieldElement =
  FieldElement(MODULUS.0.saturating_add(&U512::ONE).wrapping_div(&U512::from_u8(4)));

field!(FieldElement, MODULUS, WIDE_MODULUS, 448);

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
