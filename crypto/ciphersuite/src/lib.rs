#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("lib.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt::Debug;
#[allow(unused_imports)]
use std_shims::prelude::*;
use std_shims::io::{self, Read};

use subtle::{CtOption, ConstantTimeEq, ConditionallySelectable};
use zeroize::Zeroize;

pub use digest;
use digest::{array::ArraySize, OutputSizeUser, Digest, HashMarker};

pub use group;
use group::{
  ff::{PrimeField, PrimeFieldBits},
  Group, GroupOps,
  prime::PrimeGroup,
};
use group::GroupEncoding;

pub trait FromUniformBytes<T> {
  fn from_uniform_bytes(bytes: &T) -> Self;
}
impl<const N: usize, F: group::ff::FromUniformBytes<N>> FromUniformBytes<[u8; N]> for F {
  fn from_uniform_bytes(bytes: &[u8; N]) -> Self {
    F::from_uniform_bytes(bytes)
  }
}

/// A marker trait for fields which fleshes them out a bit more.
pub trait F: PrimeField + PrimeFieldBits + Zeroize {}
impl<Fi: PrimeField + PrimeFieldBits + Zeroize> F for Fi {}
/// A marker trait for groups which fleshes them out a bit more.
pub trait G:
  Group + GroupOps + GroupEncoding + PrimeGroup + ConstantTimeEq + ConditionallySelectable + Zeroize
{
}
impl<
    Gr: Group
      + GroupOps
      + GroupEncoding
      + PrimeGroup
      + ConstantTimeEq
      + ConditionallySelectable
      + Zeroize,
  > G for Gr
{
}

/// A `Group` type which has been wrapped into the current type.
///
/// This avoids having to re-implement all of the `Group` traits on the wrapper.
// TODO: Remove these bounds
pub trait WrappedGroup:
  'static + Send + Sync + Clone + Copy + PartialEq + Eq + Debug + Zeroize
{
  /// Scalar field element type.
  // This is available via `G::Scalar` yet `WG::G::Scalar` is ambiguous, forcing horrific accesses
  type F: F;
  /// Group element type.
  type G: Group<Scalar = Self::F> + G;
  /// Generator for the group.
  fn generator() -> Self::G;
}
impl<Gr: G<Scalar: F>> WrappedGroup for Gr {
  type F = <Gr as Group>::Scalar;
  type G = Gr;
  fn generator() -> Self::G {
    <Self::G as Group>::generator()
  }
}

/// An ID for an object.
pub trait Id {
  // The ID.
  const ID: &'static [u8];
}

/// A group with a preferred hash function.
pub trait WithPreferredHash:
  WrappedGroup<
  F: FromUniformBytes<<<Self::H as OutputSizeUser>::OutputSize as ArraySize>::ArrayType<u8>>,
>
{
  type H: Send + Clone + Digest + HashMarker;
  #[allow(non_snake_case)]
  fn hash_to_F(data: &[u8]) -> Self::F {
    Self::F::from_uniform_bytes(&Self::H::digest(data).into())
  }
}

/// A group which always encodes points canonically and supports decoding points while checking
/// they have a canonical encoding.
pub trait GroupCanonicalEncoding: WrappedGroup {
  /// Decode a point from its canonical encoding.
  ///
  /// Returns `None` if the point was invalid or not the encoding wasn't canonical.
  ///
  /// If `<Self::G as GroupEncoding>::from_bytes` already only accepts canonical encodings, this
  /// SHOULD be overriden with `<Self::G as GroupEncoding>::from_bytes(bytes)`.
  fn from_canonical_bytes(bytes: &<Self::G as GroupEncoding>::Repr) -> CtOption<Self::G> {
    let res = Self::G::from_bytes(bytes).unwrap_or(Self::generator());
    // Safe due to the bound points are always encoded canonically
    let canonical = res.to_bytes().as_ref().ct_eq(bytes.as_ref());
    CtOption::new(res, canonical)
  }
}

/// `std::io` extensions for `GroupCanonicalEncoding.`
#[allow(non_snake_case)]
pub trait GroupIo: GroupCanonicalEncoding {
  /// Read a canonical field element from something implementing `std::io::Read`.
  fn read_F<R: Read>(reader: &mut R) -> io::Result<Self::F> {
    let mut bytes = <Self::F as PrimeField>::Repr::default();
    reader.read_exact(bytes.as_mut())?;

    // `ff` mandates this is canonical
    let res = Option::<Self::F>::from(Self::F::from_repr(bytes))
      .ok_or_else(|| io::Error::other("non-canonical scalar"));
    bytes.as_mut().zeroize();

    res
  }

  /// Read a canonical point from something implementing `std::io::Read`.
  fn read_G<R: Read>(reader: &mut R) -> io::Result<Self::G> {
    let mut bytes = <Self::G as GroupEncoding>::Repr::default();
    reader.read_exact(bytes.as_mut())?;

    let res = Option::<Self::G>::from(Self::from_canonical_bytes(&bytes))
      .ok_or_else(|| io::Error::other("invalid point"))?;
    bytes.as_mut().zeroize();

    Ok(res)
  }
}
impl<Gr: GroupCanonicalEncoding> GroupIo for Gr {}

/// Unified trait defining a ciphersuite around an elliptic curve.
pub trait Ciphersuite: Id + WithPreferredHash + GroupCanonicalEncoding {}
impl<C: Id + WithPreferredHash + GroupCanonicalEncoding> Ciphersuite for C {}
