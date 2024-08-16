use zeroize::{DefaultIsZeroes, Zeroize};

use crypto_bigint::{
  U256, U512,
  modular::constant_mod::{ResidueParams, Residue},
};

const MODULUS_STR: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";

impl_modulus!(SecQ, U256, MODULUS_STR);
type ResidueType = Residue<SecQ, { SecQ::LIMBS }>;

/// The Scalar field of secq256k1.
///
/// This is equivalent to the field secp256k1 is defined over.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
#[repr(C)]
pub struct Scalar(pub(crate) ResidueType);

impl DefaultIsZeroes for Scalar {}

pub(crate) const MODULUS: U256 = U256::from_be_hex(MODULUS_STR);

const WIDE_MODULUS: U512 = U512::from_be_hex(concat!(
  "0000000000000000000000000000000000000000000000000000000000000000",
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
));

field!(
  Scalar,
  ResidueType,
  MODULUS_STR,
  MODULUS,
  WIDE_MODULUS,
  256,
  3,
  1,
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e",
  "0000000000000000000000000000000000000000000000000000000000000009",
);

impl Scalar {
  /// Perform a wide reduction, presumably to obtain a non-biased Scalar field element.
  pub fn wide_reduce(bytes: [u8; 64]) -> Scalar {
    Scalar(Residue::new(&reduce(U512::from_le_slice(bytes.as_ref()))))
  }
}

#[test]
fn test_scalar_field() {
  ff_group_tests::prime_field::test_prime_field_bits::<_, Scalar>(&mut rand_core::OsRng);
}
