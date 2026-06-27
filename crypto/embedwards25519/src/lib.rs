#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

use prime_field::subtle::{Choice, CtOption};
use ciphersuite::group::{ff::PrimeField, Group, GroupEncoding};

pub use curve25519_dalek::Scalar as FieldElement;

use short_weierstrass::{ShortWeierstrass, Affine, Projective};

prime_field::odd_prime_field!(
  Scalar,
  "0fffffffffffffffffffffffffffffffe53f4debb78ff96877063f0306eef96b",
  "0a",
  false
);

/// A ciphersuite defined around the embedwards25519 elliptic curve.
#[derive(Clone, Copy, Debug)]
pub struct Embedwards25519;

#[expect(deprecated)] // No other way to construct arbitrary `FieldElement` at compile-time :/
impl ShortWeierstrass for Embedwards25519 {
  type FieldElement = FieldElement;
  const A: FieldElement = FieldElement::from_bits(hex_literal::hex!(
    "ead3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
  ));
  const B: FieldElement = FieldElement::from_bits(hex_literal::hex!(
    "5f07603a853f20370b682036210d463e64903a23ea669d07ca26cfc13f594209"
  ));
  const PRIME_ORDER: bool = true;
  const GENERATOR: Affine<Self> = Affine::from_xy_unchecked(
    FieldElement::ONE,
    FieldElement::from_bits(hex_literal::hex!(
      "2e4118080a484a3dfbafe2199a0e36b7193581d676c0dadfa376b0265616020c"
    )),
  );
  type Scalar = Scalar;

  type Repr = [u8; 32];
  // Use an all-zero encoding for the identity as `0` isn't the `x` coordinate of an on-curve point
  const IDENTITY: [u8; 32] = [0; 32];
  fn encode_compressed(x: Self::FieldElement, odd_y: Choice) -> Self::Repr {
    // The LE `x` coordinate, with if `y` is odd in the unused 256th bit
    let mut res = [0; 32];
    res.copy_from_slice(x.to_repr().as_ref());
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
    {
      let repr: &mut [u8] = repr.as_mut();
      repr.copy_from_slice(&bytes);
    }

    (repr, odd_y)
  }
  // No points have a torsion element as this a prime-order curve
  fn has_torsion_element(_point: Projective<Self>) -> Choice {
    0.into()
  }
}

/// A point on the embedwards25519 elliptic curve.
pub type Point = Projective<Embedwards25519>;

impl ciphersuite::WrappedGroup for Embedwards25519 {
  type F = Scalar;
  type G = Point;

  fn generator() -> Self::G {
    <Point as Group>::generator()
  }
}
impl ciphersuite::Id for Embedwards25519 {
  const ID: &[u8] = b"embedwards25519";
}
impl ciphersuite::WithPreferredHash for Embedwards25519 {
  type H = blake2::Blake2b512;
}
impl ciphersuite::GroupCanonicalEncoding for Embedwards25519 {
  fn from_canonical_bytes(bytes: &<Self::G as GroupEncoding>::Repr) -> CtOption<Self::G> {
    Self::G::from_bytes(bytes)
  }
}

#[cfg(feature = "alloc")]
impl generalized_bulletproofs_ec_gadgets::DiscreteLogParameter for Embedwards25519 {
  #[expect(clippy::as_conversions)]
  type ScalarBits = typenum::U<{ <Scalar as PrimeField>::NUM_BITS as usize }>;
}

#[test]
fn test_curve() {
  ff_group_tests::group::test_prime_group_bits::<_, Point>(&mut rand_core::OsRng);
}

#[test]
fn generator() {
  assert_eq!(
    <Point as Group>::generator(),
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
  Point::random(&mut rand_core::OsRng);
}
