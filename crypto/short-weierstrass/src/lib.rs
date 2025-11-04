#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![no_std]
#![allow(non_snake_case)]

use core::fmt::Debug;

use subtle::Choice;
use zeroize::Zeroize;
use group::ff::PrimeField;

mod affine;
pub use affine::Affine;
mod projective;
pub use projective::Projective;

/// An elliptic curve represented in short Weierstrass form, with equation `y^2 = x^3 + A x + B`.
pub trait ShortWeierstrass: 'static + Sized + Debug {
  /// The field the elliptic curve is defined over.
  type FieldElement: Zeroize + PrimeField;
  /// The constant `A` from the curve equation.
  const A: Self::FieldElement;
  /// The constant `B` from the curve equation.
  const B: Self::FieldElement;
  /// If the elliptic curve is of prime order.
  const PRIME_ORDER: bool;
  /// A generator of this elliptic curve's largest prime-order subgroup.
  const GENERATOR: Affine<Self>;
  /// The scalar type for the elliptic curve's largest prime-order subgroup.
  ///
  /// This may be omitted by specifying `()`.
  type Scalar;

  /// The type used for encoding points.
  type Repr: 'static + Send + Sync + Copy + Default + AsRef<[u8]> + AsMut<[u8]>;
  /// The representation of the identity point.
  const IDENTITY: Self::Repr;
  /// Encode a compresed, on-curve point to its byte encoding.
  ///
  /// The space of potential outputs MUST exclude `Self::IDENTITY`.
  fn encode_compressed(x: Self::FieldElement, odd_y: Choice) -> Self::Repr;
  /// Decode the `x` coordinate and if the `y` coordinate is odd from a compressed representation.
  ///
  /// This MAY return any value if the bytes represent the identity.
  fn decode_compressed(bytes: &Self::Repr) -> (<Self::FieldElement as PrimeField>::Repr, Choice);

  /// If the point is outside the largest prime-order subgroup and isn't the identity point.
  ///
  /// This SHOULD immediately return `Choice::new(0)` for curves of prime order.
  fn has_torsion_element(point: Projective<Self>) -> Choice;
}
