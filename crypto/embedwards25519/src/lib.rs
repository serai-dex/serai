#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
#[allow(unused_imports)]
use std_shims::prelude::*;
#[cfg(feature = "alloc")]
use std_shims::io::{self, Read};

use prime_field::{subtle::Choice, zeroize::Zeroize};
use ciphersuite::group::{
  ff::{Field, PrimeField, FromUniformBytes},
  Group,
};

use curve25519_dalek::Scalar as DalekScalar;
pub use dalek_ff_group::Scalar as FieldElement;

use short_weierstrass::{ShortWeierstrass, Affine, Projective};

prime_field::odd_prime_field!(
  Scalar,
  "0fffffffffffffffffffffffffffffffe53f4debb78ff96877063f0306eef96b",
  "0a",
  false
);

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Embedwards25519;

#[allow(deprecated)] // No other way to construct arbitrary `FieldElement` at compile-time :/
impl ShortWeierstrass for Embedwards25519 {
  type FieldElement = FieldElement;
  const A: FieldElement = FieldElement(DalekScalar::from_bits(hex_literal::hex!(
    "ead3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
  )));
  const B: FieldElement = FieldElement(DalekScalar::from_bits(hex_literal::hex!(
    "5f07603a853f20370b682036210d463e64903a23ea669d07ca26cfc13f594209"
  )));
  const PRIME_ORDER: bool = true;
  const GENERATOR: Affine<Self> = Affine::from_xy_unchecked(
    FieldElement::ONE,
    FieldElement(DalekScalar::from_bits(hex_literal::hex!(
      "2e4118080a484a3dfbafe2199a0e36b7193581d676c0dadfa376b0265616020c"
    ))),
  );
  type Scalar = Scalar;

  type Repr = [u8; 32];
  // Use an all-zero encoding for the identity as `0` isn't the `x` coordinate of an on-curve point
  const IDENTITY: [u8; 32] = [0; 32];
  fn encode_compressed(x: Self::FieldElement, odd_y: Choice) -> Self::Repr {
    // The LE `x` coordinate, with if `y` is odd in the unused 256th bit
    let mut res = [0; 32];
    res.as_mut().copy_from_slice(x.to_repr().as_ref());
    res[31] |= odd_y.unwrap_u8() << 7;
    res
  }
  fn decode_compressed(bytes: &Self::Repr) -> (<Self::FieldElement as PrimeField>::Repr, Choice) {
    // Extract and clear the sign bit
    let mut bytes = *bytes;
    let odd_y = Choice::from(bytes[31] >> 7);
    bytes[31] &= u8::MAX >> 1;

    // Copy from the point's representation to the field's
    let mut repr = <Self::FieldElement as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&bytes);

    (repr, odd_y)
  }
  // No points have a torsion element as this a prime-order curve
  fn has_torsion_element(_point: Projective<Self>) -> Choice {
    0.into()
  }
}

pub type Point = Projective<Embedwards25519>;

impl ciphersuite::Ciphersuite for Embedwards25519 {
  type F = Scalar;
  type G = Point;
  type H = blake2::Blake2b512;

  const ID: &'static [u8] = b"embedwards25519";

  fn generator() -> Self::G {
    Point::generator()
  }

  /// `hash_to_F` is implemented with a naive concatenation of the `dst` and `data`, allowing
  /// transposition between the two. This means `dst: b"abc", data: b"def"`, will produce the same
  /// scalar as `dst: "abcdef", data: b""`. Please use carefully, not letting `dst` valuess be
  /// substrings of each other.
  fn hash_to_F(dst: &[u8], data: &[u8]) -> Self::F {
    use blake2::Digest;
    <Scalar as FromUniformBytes<64>>::from_uniform_bytes(
      &Self::H::digest([dst, data].concat()).into(),
    )
  }

  // We override the provided impl, which compares against the reserialization, because
  // we already require canonicity
  #[cfg(feature = "alloc")]
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

#[cfg(feature = "alloc")]
impl generalized_bulletproofs_ec_gadgets::DiscreteLogParameter for Embedwards25519 {
  type ScalarBits = generic_array::typenum::U<{ <Scalar as PrimeField>::NUM_BITS as usize }>;
}

#[test]
fn test_curve() {
  ff_group_tests::group::test_prime_group_bits::<_, Point>(&mut rand_core::OsRng);
}

#[test]
fn generator() {
  use ciphersuite::group::{Group, GroupEncoding};
  assert_eq!(
    Point::generator(),
    Point::from_bytes(&hex_literal::hex!(
      "0100000000000000000000000000000000000000000000000000000000000000"
    ))
    .unwrap()
  );
}

#[test]
fn zero_x_is_off_curve() {
  assert!(bool::from(
    Affine::<Embedwards25519>::decompress(FieldElement::ZERO, 1.into()).is_none()
  ));
}

// Checks random won't infinitely loop
#[test]
fn random() {
  use ciphersuite::group::Group;
  Point::random(&mut rand_core::OsRng);
}
