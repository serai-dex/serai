#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

#[allow(unused_imports)]
use std_shims::prelude::*;
#[cfg(any(feature = "alloc", feature = "std"))]
use std_shims::io::{self, Read};

use generic_array::typenum::{Sum, Diff, Quot, U, U1, U2};
use ciphersuite::group::{
  ff::{PrimeField, FromUniformBytes},
  Group,
};

prime_field::odd_prime_field!(
  Scalar,
  "0fffffffffffffffffffffffffffffffe53f4debb78ff96877063f0306eef96b",
  "0a",
  false
);

pub use dalek_ff_group::Scalar as FieldElement;

mod point;
pub use point::Point;

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

/// Ciphersuite for Embedwards25519.
///
/// hash_to_F is implemented with a naive concatenation of the dst and data, allowing transposition
/// between the two. This means `dst: b"abc", data: b"def"`, will produce the same scalar as
/// `dst: "abcdef", data: b""`. Please use carefully, not letting dsts be substrings of each other.
#[derive(Clone, Copy, PartialEq, Eq, Debug, zeroize::Zeroize)]
pub struct Embedwards25519;
impl ciphersuite::Ciphersuite for Embedwards25519 {
  type F = Scalar;
  type G = Point;
  type H = blake2::Blake2b512;

  const ID: &'static [u8] = b"embedwards25519";

  fn generator() -> Self::G {
    Point::generator()
  }

  fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
    use blake2::Digest;
    <Scalar as FromUniformBytes<64>>::from_uniform_bytes(
      &Self::H::digest([dst, data].concat()).into(),
    )
  }

  // We override the provided impl, which compares against the reserialization, because
  // we already require canonicity
  #[cfg(any(feature = "alloc", feature = "std"))]
  #[allow(non_snake_case)]
  fn read_G<R: Read>(reader: &mut R) -> io::Result<Self::G> {
    use ciphersuite::group::GroupEncoding;

    let mut encoding = <Self::G as GroupEncoding>::Repr::default();
    reader.read_exact(encoding.as_mut())?;

    let point = Option::<Self::G>::from(Self::G::from_bytes(&encoding))
      .ok_or_else(|| io::Error::other("invalid point"))?;
    Ok(point)
  }
}

impl generalized_bulletproofs_ec_gadgets::DiscreteLogParameters for Embedwards25519 {
  type ScalarBits = U<{ Scalar::NUM_BITS as usize }>;
  type XCoefficients = Quot<Sum<Self::ScalarBits, U1>, U2>;
  type XCoefficientsMinusOne = Diff<Self::XCoefficients, U1>;
  type YxCoefficients = Diff<Quot<Sum<Sum<Self::ScalarBits, U1>, U1>, U2>, U2>;
}
