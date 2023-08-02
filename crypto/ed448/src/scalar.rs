use zeroize::{DefaultIsZeroes, Zeroize};

use crypto_bigint::{
  U448, U896, U1024,
  modular::constant_mod::{ResidueParams, Residue},
};

const MODULUS_STR: &str = concat!(
  "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
);

impl_modulus!(ScalarModulus, U448, MODULUS_STR);
type ResidueType = Residue<ScalarModulus, { ScalarModulus::LIMBS }>;

/// Ed448 Scalar field element.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct Scalar(pub(crate) ResidueType);

impl DefaultIsZeroes for Scalar {}

// 2**446 - 13818066809895115352007386748515426880336692474882178609894547503885
pub(crate) const MODULUS: U448 = U448::from_be_hex(MODULUS_STR);

const WIDE_MODULUS: U896 = U896::from_be_hex(concat!(
  "00000000000000000000000000000000000000000000000000000000",
  "00000000000000000000000000000000000000000000000000000000",
  "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
));

const WIDE_REDUCTION_MODULUS: NonZero<U1024> = NonZero::from_uint(U1024::from_be_hex(concat!(
  "00000000000000000000000000000000",
  "00000000000000000000000000000000000000000000000000000000",
  "00000000000000000000000000000000000000000000000000000000",
  "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
)));

field!(
  Scalar,
  ResidueType,
  MODULUS_STR,
  MODULUS,
  WIDE_MODULUS,
  446,
  2,
  concat!(
    "04000000000000000000000000000000000000000000000000000000",
    "00000000000000000000000000000000000000000000000000000000",
  ),
);

impl Scalar {
  /// Perform a wide reduction to obtain a non-biased Scalar.
  pub fn wide_reduce(bytes: [u8; 114]) -> Scalar {
    let mut bytes_128 = [0; 128];
    bytes_128[.. 114].copy_from_slice(&bytes);
    let wide = U1024::from_le_slice(&bytes_128);
    Scalar(Residue::new(&U448::from_le_slice(
      &wide.rem(&WIDE_REDUCTION_MODULUS).to_le_bytes()[.. 56],
    )))
  }
}

#[test]
fn test_scalar() {
  ff_group_tests::prime_field::test_prime_field_bits::<_, Scalar>(&mut rand_core::OsRng);
}
