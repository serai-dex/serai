#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![no_std]

use sha2::digest::array::{typenum::U33, Array};
use k256::elliptic_curve::{
  subtle::{Choice, CtOption, ConstantTimeEq as _, ConditionallySelectable as _},
  zeroize::Zeroize,
  group::{ff::PrimeField, Group, GroupEncoding},
  sec1::Tag,
};

prime_field::odd_prime_field!(
  Scalar,
  "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
  "03",
  true
);

pub use k256::Scalar as FieldElement;

use short_weierstrass::{ShortWeierstrass, Affine, Projective};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Secq256k1;
impl Zeroize for Secq256k1 {
  fn zeroize(&mut self) {
    let Self = self;
  }
}

impl ShortWeierstrass for Secq256k1 {
  type FieldElement = FieldElement;
  const A: FieldElement = FieldElement::ZERO;
  const B: FieldElement = {
    let two = FieldElement::ONE.add(&FieldElement::ONE);
    let four = two.add(&two);
    let six = four.add(&two);
    six.add(&FieldElement::ONE)
  };
  const PRIME_ORDER: bool = true;
  const GENERATOR: Affine<Self> = Affine::from_xy_unchecked(FieldElement::ONE, {
    let y_be =
      hex_literal::hex!("0c7c97045a2074634909abdf82c9bd0248916189041f2af0c1b800d1ffc278c0");
    let mut res = FieldElement::ZERO;
    let mut i = 0;
    while i < 32 {
      let mut j = 0;
      while j < 8 {
        // Shift over the existing result
        res = res.add(&res);
        // Add this bit, if set
        if ((y_be[i] >> (8 - 1 - j)) & 1) == 1 {
          res = res.add(&FieldElement::ONE);
        }
        j += 1;
      }
      i += 1;
    }
    res
  });
  type Scalar = Scalar;

  type Repr = Array<u8, U33>;
  /// Use the SEC1-encoded identity point, which happens to be all zeroes
  const IDENTITY: Self::Repr = Array([0; 33]);
  fn encode_compressed(x: Self::FieldElement, odd_y: Choice) -> Self::Repr {
    let mut res = Array([0; 33]);
    res[0] = <_>::conditional_select(
      &u8::from(Tag::CompressedEvenY),
      &u8::from(Tag::CompressedOddY),
      odd_y,
    );
    {
      let res: &mut [u8] = res.as_mut();
      res[1 ..].copy_from_slice(x.to_repr().as_ref());
    }
    res
  }
  fn decode_compressed(bytes: &Self::Repr) -> (<Self::FieldElement as PrimeField>::Repr, Choice) {
    // Parse out if `y` is odd
    let odd_y = bytes[0].ct_eq(&u8::from(Tag::CompressedOddY));
    // Check if the tag was malleated
    let expected_tag = <_>::conditional_select(
      &u8::from(Tag::CompressedEvenY),
      &u8::from(Tag::CompressedOddY),
      odd_y,
    );
    let invalid = !bytes[0].ct_eq(&expected_tag);

    // Copy the alleged `x` coordinate, overwriting with `0xffffff...` if the sign byte was
    // malleated (causing the `x` coordinate to be invalid)
    let mut x = <Self::FieldElement as PrimeField>::Repr::default();
    {
      let x: &mut [u8] = x.as_mut();
      for i in 0 .. 32 {
        x[i] = <_>::conditional_select(&bytes[1 + i], &u8::MAX, invalid);
      }
    }

    (x, odd_y)
  }
  // No points have a torsion element as this a prime-order curve
  fn has_torsion_element(_point: Projective<Self>) -> Choice {
    0.into()
  }
}

pub type Point = Projective<Secq256k1>;

impl ciphersuite::WrappedGroup for Secq256k1 {
  type F = Scalar;
  type G = Point;

  fn generator() -> Self::G {
    <Point as Group>::generator()
  }
}
impl ciphersuite::Id for Secq256k1 {
  const ID: &[u8] = b"secq256k1";
}
impl ciphersuite::GroupCanonicalEncoding for Secq256k1 {
  fn from_canonical_bytes(bytes: &<Self::G as GroupEncoding>::Repr) -> CtOption<Self::G> {
    Self::G::from_bytes(bytes)
  }
}
impl ciphersuite::WithPreferredHash for Secq256k1 {
  type H = sha2::Sha512;
}

#[cfg(feature = "alloc")]
impl generalized_bulletproofs_ec_gadgets::DiscreteLogParameter for Secq256k1 {
  #[expect(clippy::as_conversions)]
  type ScalarBits = sha2::digest::array::typenum::U<{ Scalar::NUM_BITS as usize }>;
}

#[test]
fn test_curve() {
  ff_group_tests::group::test_prime_group_bits::<_, Point>(&mut rand_core::OsRng);
}

#[test]
fn generator() {
  use ciphersuite::group::GroupEncoding as _;
  assert_eq!(
    <Point as Group>::generator(),
    Point::from_bytes(&Array(hex_literal::hex!(
      "020000000000000000000000000000000000000000000000000000000000000001"
    )))
    .unwrap()
  );
}

#[test]
fn zero_x_is_off_curve() {
  assert!(bool::from(Affine::<Secq256k1>::decompress(FieldElement::ZERO, 1.into()).is_none()));
}

// Checks random won't infinitely loop
#[test]
fn random() {
  Point::random(&mut rand_core::OsRng);
}
