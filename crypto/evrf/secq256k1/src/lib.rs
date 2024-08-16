#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

use generic_array::typenum::{Sum, Diff, Quot, U, U1, U2};
use ciphersuite::group::{ff::PrimeField, Group};

#[macro_use]
mod backend;

mod scalar;
pub use scalar::Scalar;

pub use k256::Scalar as FieldElement;

mod point;
pub use point::Point;

/// Ciphersuite for Secq256k1.
///
/// hash_to_F is implemented with a naive concatenation of the dst and data, allowing transposition
/// between the two. This means `dst: b"abc", data: b"def"`, will produce the same scalar as
/// `dst: "abcdef", data: b""`. Please use carefully, not letting dsts be substrings of each other.
#[derive(Clone, Copy, PartialEq, Eq, Debug, zeroize::Zeroize)]
pub struct Secq256k1;
impl ciphersuite::Ciphersuite for Secq256k1 {
  type F = Scalar;
  type G = Point;
  type H = blake2::Blake2b512;

  const ID: &'static [u8] = b"secq256k1";

  fn generator() -> Self::G {
    Point::generator()
  }

  fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
    use blake2::Digest;
    Scalar::wide_reduce(Self::H::digest([dst, data].concat()).as_slice().try_into().unwrap())
  }
}

impl generalized_bulletproofs_ec_gadgets::DiscreteLogParameters for Secq256k1 {
  type ScalarBits = U<{ Scalar::NUM_BITS as usize }>;
  type XCoefficients = Quot<Sum<Self::ScalarBits, U1>, U2>;
  type XCoefficientsMinusOne = Diff<Self::XCoefficients, U1>;
  type YxCoefficients = Diff<Quot<Sum<Sum<Self::ScalarBits, U1>, U1>, U2>, U2>;
}
