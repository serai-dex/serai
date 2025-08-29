#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
#[allow(unused_imports)]
use std_shims::prelude::*;
#[cfg(feature = "alloc")]
use std_shims::io::{self, Read};

// Doesn't use the `generic-array 0.14` exported by `k256::elliptic_curve` as we need `1.0`
use generic_array::{typenum::U33, GenericArray};
use k256::elliptic_curve::{
  subtle::{Choice, ConstantTimeEq, ConditionallySelectable},
  zeroize::Zeroize,
  group::{
    ff::{PrimeField, FromUniformBytes},
    Group,
  },
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
  fn zeroize(&mut self) {}
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

  type Repr = GenericArray<u8, U33>;
  /// Use the SEC1-encoded identity point, which happens to be all zeroes
  const IDENTITY: Self::Repr = GenericArray::from_array([0; 33]);
  fn encode_compressed(x: Self::FieldElement, odd_y: Choice) -> Self::Repr {
    let mut res = GenericArray::default();
    res[0] =
      <_>::conditional_select(&(Tag::CompressedEvenY as u8), &(Tag::CompressedOddY as u8), odd_y);
    {
      let res: &mut [u8] = res.as_mut();
      res[1 ..].copy_from_slice(x.to_repr().as_ref());
    }
    res
  }
  fn decode_compressed(bytes: &Self::Repr) -> (<Self::FieldElement as PrimeField>::Repr, Choice) {
    // Parse out if `y` is odd
    let odd_y = bytes[0].ct_eq(&(Tag::CompressedOddY as u8));
    // Check if the tag was malleated
    let expected_tag =
      <_>::conditional_select(&(Tag::CompressedEvenY as u8), &(Tag::CompressedOddY as u8), odd_y);
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

impl ciphersuite::Ciphersuite for Secq256k1 {
  type F = Scalar;
  type G = Point;
  type H = blake2::Blake2b512;

  const ID: &'static [u8] = b"secq256k1";

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
impl generalized_bulletproofs_ec_gadgets::DiscreteLogParameter for Secq256k1 {
  type ScalarBits = generic_array::typenum::U<{ Scalar::NUM_BITS as usize }>;
}

#[test]
fn test_curve() {
  ff_group_tests::group::test_prime_group_bits::<_, Point>(&mut rand_core::OsRng);
}

#[test]
fn generator() {
  use ciphersuite::group::GroupEncoding;
  assert_eq!(
    Point::generator(),
    Point::from_bytes(GenericArray::from_slice(&hex_literal::hex!(
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
