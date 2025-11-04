#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![no_std]

prime_field::odd_prime_field!(
  FieldElement,
  // 2**448 - 2**224 - 1
  concat!(
    "00",
    "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe",
    "ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
  ),
  "07",
  false
);

prime_field::odd_prime_field!(
  Scalar,
  concat!(
    "00",
    "3fffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3",
  ),
  "02",
  false
);

mod point;
pub use point::Point;

mod ciphersuite;

pub(crate) fn u8_from_bool(bit_ref: &mut bool) -> u8 {
  use core::hint::black_box;
  use prime_field::zeroize::Zeroize;

  let bit_ref = black_box(bit_ref);

  let mut bit = black_box(*bit_ref);
  let res = black_box(u8::from(bit));
  bit.zeroize();
  debug_assert!((res | 1) == 1);

  bit_ref.zeroize();
  res
}
