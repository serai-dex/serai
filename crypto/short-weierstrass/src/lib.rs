#![cfg_attr(docsrs, feature(doc_auto_cfg))]
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
///
/// This elliptic curve is expected to be of prime order. If a generator of the elliptic curve has
/// a composite order, the elliptic curve is defined solely as its largest odd-prime-order
/// subgroup, further considered the entire group/elliptic curve.
pub trait ShortWeierstrass: 'static + Sized + Debug {
  /// The field the elliptic curve is defined over.
  type FieldElement: Zeroize + PrimeField;
  /// The constant `A` from the curve equation.
  const A: Self::FieldElement;
  /// The constant `B` from the curve equation.
  const B: Self::FieldElement;
  /// A generator of this elliptic curve.
  const GENERATOR: Affine<Self>;
  /// The scalar type.
  ///
  /// This may be omitted by specifying `()`.
  type Scalar;

  /// The type used for encoding points.
  type Repr: 'static + Send + Sync + Copy + Default + AsRef<[u8]> + AsMut<[u8]>;
  /// The representation of the identity point.
  const IDENTITY: Self::Repr;
  /// Compress an affine point its byte encoding.
  ///
  /// The space of potential outputs MUST exclude `Self::IDENTITY`.
  fn compress(x: Self::FieldElement, odd_y: Choice) -> Self::Repr;
  /// Decode a compressed point.
  ///
  /// This is expected to return the `x` coordinate and if the `y` coordinate is odd.
  fn decode_compressed(bytes: &Self::Repr) -> (<Self::FieldElement as PrimeField>::Repr, Choice);
}
