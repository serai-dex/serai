#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![no_std]
#![allow(non_snake_case)]

use core::fmt::Debug;

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
  /// A generator of this elliptic curve.
  const GENERATOR: Affine<Self>;
  /// The scalar type.
  ///
  /// This may be omitted by specifying `()`.
  type Scalar;
}
