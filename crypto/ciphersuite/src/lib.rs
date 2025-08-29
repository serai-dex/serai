#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("lib.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt::Debug;
#[cfg(feature = "alloc")]
#[allow(unused_imports)]
use std_shims::prelude::*;
#[cfg(feature = "alloc")]
use std_shims::io::{self, Read};

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;
use subtle::ConstantTimeEq;

pub use digest;
use digest::{array::ArraySize, block_api::BlockSizeUser, OutputSizeUser, Digest, HashMarker};
use transcript::SecureDigest;

pub use group;
use group::{
  ff::{Field, PrimeField, PrimeFieldBits},
  Group, GroupOps,
  prime::PrimeGroup,
};
#[cfg(feature = "alloc")]
use group::GroupEncoding;

pub trait FromUniformBytes<T> {
  fn from_uniform_bytes(bytes: &T) -> Self;
}
impl<const N: usize, F: group::ff::FromUniformBytes<N>> FromUniformBytes<[u8; N]> for F {
  fn from_uniform_bytes(bytes: &[u8; N]) -> Self {
    F::from_uniform_bytes(bytes)
  }
}

/// Unified trait defining a ciphersuite around an elliptic curve.
pub trait Ciphersuite:
  'static + Send + Sync + Clone + Copy + PartialEq + Eq + Debug + Zeroize
{
  /// Scalar field element type.
  // This is available via G::Scalar yet `C::G::Scalar` is ambiguous, forcing horrific accesses
  type F: PrimeField
    + PrimeFieldBits
    + Zeroize
    + FromUniformBytes<<<Self::H as OutputSizeUser>::OutputSize as ArraySize>::ArrayType<u8>>;
  /// Group element type.
  type G: Group<Scalar = Self::F> + GroupOps + PrimeGroup + Zeroize + ConstantTimeEq;
  /// Hash algorithm used with this curve.
  // Requires BlockSizeUser so it can be used within Hkdf which requires that.
  type H: Send + Clone + BlockSizeUser + Digest + HashMarker + SecureDigest;

  /// ID for this curve.
  const ID: &'static [u8];

  /// Generator for the group.
  // While group does provide this in its API, privacy coins may want to use a custom basepoint
  fn generator() -> Self::G;

  #[allow(non_snake_case)]
  fn hash_to_F(data: &[u8]) -> Self::F {
    Self::F::from_uniform_bytes(&Self::H::digest(data).into())
  }

  /// Generate a random non-zero scalar.
  #[allow(non_snake_case)]
  fn random_nonzero_F<R: RngCore + CryptoRng>(rng: &mut R) -> Self::F {
    let mut res;
    while {
      res = Self::F::random(&mut *rng);
      res.ct_eq(&Self::F::ZERO).into()
    } {}
    res
  }

  /// Read a canonical scalar from something implementing std::io::Read.
  #[cfg(feature = "alloc")]
  #[allow(non_snake_case)]
  fn read_F<R: Read>(reader: &mut R) -> io::Result<Self::F> {
    let mut encoding = <Self::F as PrimeField>::Repr::default();
    reader.read_exact(encoding.as_mut())?;

    // ff mandates this is canonical
    let res = Option::<Self::F>::from(Self::F::from_repr(encoding))
      .ok_or_else(|| io::Error::other("non-canonical scalar"));
    encoding.as_mut().zeroize();
    res
  }

  /// Read a canonical point from something implementing std::io::Read.
  ///
  /// The provided implementation is safe so long as `GroupEncoding::to_bytes` always returns a
  /// canonical serialization.
  #[cfg(feature = "alloc")]
  #[allow(non_snake_case)]
  fn read_G<R: Read>(reader: &mut R) -> io::Result<Self::G> {
    let mut encoding = <Self::G as GroupEncoding>::Repr::default();
    reader.read_exact(encoding.as_mut())?;

    let point = Option::<Self::G>::from(Self::G::from_bytes(&encoding))
      .ok_or_else(|| io::Error::other("invalid point"))?;
    if point.to_bytes().as_ref() != encoding.as_ref() {
      Err(io::Error::other("non-canonical point"))?;
    }
    Ok(point)
  }
}
