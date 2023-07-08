use zeroize::{DefaultIsZeroes, Zeroize};

use crypto_bigint::{
  U448, U896,
  modular::constant_mod::{ResidueParams, Residue},
};

const MODULUS_STR: &str = concat!(
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
);

impl_modulus!(FieldModulus, U448, MODULUS_STR);
pub(crate) type ResidueType = Residue<FieldModulus, { FieldModulus::LIMBS }>;

/// Ed448 field element.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct FieldElement(pub(crate) ResidueType);

impl DefaultIsZeroes for FieldElement {}

// 2**448 - 2**224 - 1
const MODULUS: U448 = U448::from_be_hex(MODULUS_STR);

const WIDE_MODULUS: U896 = U896::from_be_hex(concat!(
  "00000000000000000000000000000000000000000000000000000000",
  "00000000000000000000000000000000000000000000000000000000",
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
));

pub(crate) const Q_4: FieldElement = FieldElement(ResidueType::new(
  &MODULUS.saturating_add(&U448::ONE).wrapping_div(&U448::from_u8(4)),
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
    "31000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000",
  ),
);

#[test]
fn test_field() {
  ff_group_tests::prime_field::test_prime_field_bits::<_, FieldElement>(&mut rand_core::OsRng);
}
