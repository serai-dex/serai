#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("lib.md")]
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt::Debug;
#[cfg(any(feature = "alloc", feature = "std"))]
use std_shims::io::{self, Read};

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;
use subtle::ConstantTimeEq;

use digest::{core_api::BlockSizeUser, Digest, HashMarker};
use transcript::SecureDigest;

pub use group;
use group::{
  ff::{Field, PrimeField, PrimeFieldBits},
  Group, GroupOps,
  prime::PrimeGroup,
};
#[cfg(any(feature = "alloc", feature = "std"))]
use group::GroupEncoding;

#[cfg(feature = "dalek")]
mod dalek;
#[cfg(feature = "ristretto")]
pub use dalek::Ristretto;
#[cfg(feature = "ed25519")]
pub use dalek::Ed25519;

#[cfg(feature = "kp256")]
mod kp256;
#[cfg(feature = "secp256k1")]
pub use kp256::Secp256k1;
#[cfg(feature = "p256")]
pub use kp256::P256;

#[cfg(feature = "ed448")]
mod ed448;
#[cfg(feature = "ed448")]
pub use ed448::*;

/// Unified trait defining a ciphersuite around an elliptic curve.
pub trait Ciphersuite:
  'static + Send + Sync + Clone + Copy + PartialEq + Eq + Debug + Zeroize
{
  /// Scalar field element type.
  // This is available via G::Scalar yet `C::G::Scalar` is ambiguous, forcing horrific accesses
  type F: PrimeField + PrimeFieldBits + Zeroize;
  /// Group element type.
  type G: Group<Scalar = Self::F> + GroupOps + PrimeGroup + Zeroize + ConstantTimeEq;
  /// Hash algorithm used with this curve.
  // Requires BlockSizeUser so it can be used within Hkdf which requies that.
  type H: Send + Clone + BlockSizeUser + Digest + HashMarker + SecureDigest;

  /// ID for this curve.
  const ID: &'static [u8];

  /// Generator for the group.
  // While group does provide this in its API, privacy coins may want to use a custom basepoint
  fn generator() -> Self::G;

  /// Hash the provided domain-separation tag and message to a scalar. Ciphersuites MAY naively
  /// prefix the tag to the message, enabling transpotion between the two. Accordingly, this
  /// function should NOT be used in any scheme where one tag is a valid substring of another
  /// UNLESS the specific Ciphersuite is verified to handle the DST securely.
  ///
  /// Verifying specific ciphersuites have secure tag handling is not recommended, due to it
  /// breaking the intended modularity of ciphersuites. Instead, component-specific tags with
  /// further purpose tags are recommended ("Schnorr-nonce", "Schnorr-chal").
  #[allow(non_snake_case)]
  fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F;

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
  #[cfg(any(feature = "alloc", feature = "std"))]
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
  #[cfg(any(feature = "alloc", feature = "std"))]
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
