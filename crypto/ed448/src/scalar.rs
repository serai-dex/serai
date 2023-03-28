use zeroize::Zeroize;

use crypto_bigint::{U512, U1024};

/// Ed448 Scalar field element.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug, Zeroize)]
pub struct Scalar(pub(crate) U512);

const MODULUS_STR: &str = concat!(
  "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  "7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
);

// 2**446 - 13818066809895115352007386748515426880336692474882178609894547503885
pub(crate) const MODULUS: Scalar = Scalar(U512::from_be_hex(concat!(
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

field!(
  Scalar,
  MODULUS_STR,
  MODULUS,
  WIDE_MODULUS,
  446,
  concat!(
    "7a22ac554961bc91aac7e2463961b610481b6bd7a46d27e2f41165beffffffff",
    "ffffffffffffffffffffffffffffffffffffffffffffff1f0000000000000000",
  ),
  2,
  concat!(
    "f24458ab92c27823558fc58d72c26c219036d6ae49db4ec4e923ca7cffffffff",
    "ffffffffffffffffffffffffffffffffffffffffffffff3f0000000000000000",
  ),
  concat!(
    "0400000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000000",
  ),
);

impl Scalar {
  /// Perform a wide reduction to obtain a non-biased Scalar.
  pub fn wide_reduce(bytes: [u8; 114]) -> Scalar {
    Scalar(reduce(U1024::from_le_slice(&[bytes.as_ref(), &[0; 14]].concat())))
  }
}

#[test]
fn test_scalar() {
  ff_group_tests::prime_field::test_prime_field_bits::<_, Scalar>(&mut rand_core::OsRng);
}
