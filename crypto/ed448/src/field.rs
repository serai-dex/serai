use zeroize::{DefaultIsZeroes, Zeroize};

use crypto_bigint::{
  U512, U1024,
  modular::constant_mod::{ResidueParams, Residue},
};

const MODULUS_PADDED_STR: &str = concat!(
  "00000000000000",
  "00",
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);

impl_modulus!(FieldModulus, U512, MODULUS_PADDED_STR);
pub(crate) type ResidueType = Residue<FieldModulus, { FieldModulus::LIMBS }>;

/// Ed448 field element.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct FieldElement(pub(crate) ResidueType);

impl DefaultIsZeroes for FieldElement {}

const MODULUS_STR: &str = concat!(
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);

// 2**448 - 2**224 - 1
pub(crate) const MODULUS: U512 = U512::from_be_hex(concat!(
  "00000000000000",
  "00",
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
));

const WIDE_MODULUS: U1024 = U1024::from_be_hex(concat!(
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "00000000000000",
  "00",
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
));

pub(crate) const Q_4: FieldElement = FieldElement(ResidueType::new(
  &MODULUS.saturating_add(&U512::ONE).wrapping_div(&U512::from_u8(4)),
));

field!(
  FieldElement,
  ResidueType,
  MODULUS_STR,
  MODULUS,
  WIDE_MODULUS,
  448,
  7,
  concat!(
    "3100000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
  ),
);

#[test]
fn test_field() {
  ff_group_tests::prime_field::test_prime_field_bits::<_, FieldElement>(&mut rand_core::OsRng);
}
