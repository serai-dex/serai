use zeroize::{DefaultIsZeroes, Zeroize};

use crypto_bigint::{
  U512, U1024,
  modular::constant_mod::{ResidueParams, Residue},
};

const MODULUS_PADDED_STR: &str = concat!(
  "00000000000000",
  "00",
  "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
);

impl_modulus!(ScalarModulus, U512, MODULUS_PADDED_STR);
type ResidueType = Residue<ScalarModulus, { ScalarModulus::LIMBS }>;

/// Ed448 Scalar field element.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Scalar(pub(crate) ResidueType);

impl DefaultIsZeroes for Scalar {}

const MODULUS_STR: &str = concat!(
  "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
);

// 2**446 - 13818066809895115352007386748515426880336692474882178609894547503885
pub(crate) const MODULUS: U512 = U512::from_be_hex(concat!(
  "00000000000000",
  "00",
  "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
));

const WIDE_MODULUS: U1024 = U1024::from_be_hex(concat!(
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "00000000000000",
  "00",
  "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
));

field!(
  Scalar,
  ResidueType,
  MODULUS_STR,
  MODULUS,
  WIDE_MODULUS,
  446,
  2,
  concat!(
    "0400000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
  ),
);

impl Scalar {
  /// Perform a wide reduction to obtain a non-biased Scalar.
  pub fn wide_reduce(bytes: [u8; 114]) -> Scalar {
    Scalar(Residue::new(&reduce(U1024::from_le_slice(&[bytes.as_ref(), &[0; 14]].concat()))))
  }
}

#[test]
fn test_scalar() {
  ff_group_tests::prime_field::test_prime_field_bits::<_, Scalar>(&mut rand_core::OsRng);
}
