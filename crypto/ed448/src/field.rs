use zeroize::Zeroize;

use crypto_bigint::{U512, U1024};

use crate::field;

/// Ed448 field element.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Zeroize)]
pub struct FieldElement(pub(crate) U512);

const MODULUS_STR: &str = concat!(
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);

// 2**448 - 2**224 - 1
pub(crate) const MODULUS: FieldElement = FieldElement(U512::from_be_hex(concat!(
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
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
));

pub(crate) const Q_4: FieldElement =
  FieldElement(MODULUS.0.saturating_add(&U512::ONE).wrapping_div(&U512::from_u8(4)));

field!(FieldElement, MODULUS_STR, MODULUS, WIDE_MODULUS, 448);

#[test]
fn test_field() {
  // TODO: Move to test_prime_field_bits once the impl is finished
  ff_group_tests::prime_field::test_prime_field::<_, FieldElement>(&mut rand_core::OsRng);
}
