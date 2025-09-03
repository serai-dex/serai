#![allow(deprecated)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![no_std] // Prevents writing new code, in what should be a simple wrapper, which requires std
#![doc = include_str!("../README.md")]
#![allow(clippy::redundant_closure_call)]

pub use dalek_ff_group::{Scalar, EdwardsPoint, RistrettoPoint, Ed25519, Ristretto};

type ThirtyTwoArray = [u8; 32];
prime_field::odd_prime_field_with_specific_repr!(
  FieldElement,
  "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
  "02",
  false,
  crate::ThirtyTwoArray
);

impl FieldElement {
  /// Create a FieldElement from a `crypto_bigint::U256`.
  ///
  /// This will reduce the `U256` by the modulus, into a member of the field.
  #[deprecated]
  pub const fn from_u256(u256: &crypto_bigint_05::U256) -> Self {
    const MODULUS: crypto_bigint::U256 = crypto_bigint::U256::from_be_hex(
      "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
    );
    let mut u256 = crypto_bigint::U256::from_words(*u256.as_words());
    loop {
      let result = FieldElement::from_bytes(&u256.to_le_bytes());
      if let Some(result) = result {
        return result;
      }
      u256 = u256.wrapping_sub(&MODULUS);
    }
  }

  /// Create a `FieldElement` from the reduction of a 512-bit number.
  ///
  /// The bytes are interpreted in little-endian format.
  #[deprecated]
  pub fn wide_reduce(value: [u8; 64]) -> Self {
    <FieldElement as prime_field::ff::FromUniformBytes<_>>::from_uniform_bytes(&value)
  }
}
