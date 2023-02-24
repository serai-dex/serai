use zeroize::Zeroize;

use crypto_bigint::{U512, U1024};

pub use crate::field;

#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Zeroize)]
pub struct Scalar(pub(crate) U512);

// 2**446 - 13818066809895115352007386748515426880336692474882178609894547503885
pub const MODULUS: Scalar = Scalar(U512::from_be_hex(concat!(
  "00000000000000",
  "00",
  "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
)));

const WIDE_MODULUS: U1024 = U1024::from_be_hex(concat!(
  "0000000000000000000000000000000000000000000000000000000000000000",
  "0000000000000000000000000000000000000000000000000000000000000000",
  "00000000000000",
  "00",
  "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
));

field!(Scalar, MODULUS, WIDE_MODULUS, 446);

impl Scalar {
  pub fn wide_reduce(bytes: [u8; 114]) -> Scalar {
    Scalar(reduce(U1024::from_le_slice(&[bytes.as_ref(), &[0; 14]].concat())))
  }
}

#[test]
fn test_scalar_field() {
  // TODO: Move to test_prime_field_bits once the impl is finished
  ff_group_tests::prime_field::test_prime_field::<_, Scalar>(&mut rand_core::OsRng);
}
