use core::{ops::Mul, fmt::Debug};

use thiserror::Error;

use rand_core::{RngCore, CryptoRng};

use group::{ff::PrimeField, Group, GroupOps, prime::PrimeGroup};

#[cfg(any(test, feature = "dalek"))]
mod dalek;
#[cfg(any(test, feature = "ristretto"))]
pub use dalek::{Ristretto, IetfRistrettoHram};
#[cfg(feature = "ed25519")]
pub use dalek::{Ed25519, IetfEd25519Hram};

#[cfg(feature = "kp256")]
mod kp256;
#[cfg(feature = "secp256k1")]
pub use kp256::{Secp256k1, NonIetfSecp256k1Hram};
#[cfg(feature = "p256")]
pub use kp256::{P256, IetfP256Hram};

/// Set of errors for curve-related operations, namely encoding and decoding
#[derive(Clone, Error, Debug)]
pub enum CurveError {
  #[error("invalid length for data (expected {0}, got {0})")]
  InvalidLength(usize, usize),
  #[error("invalid scalar")]
  InvalidScalar,
  #[error("invalid point")]
  InvalidPoint,
}

/// Unified trait to manage a field/group
// This should be moved into its own crate if the need for generic cryptography over ff/group
// continues, which is the exact reason ff/group exists (to provide a generic interface)
// elliptic-curve exists, yet it doesn't really serve the same role, nor does it use &[u8]/Vec<u8>
// It uses GenericArray which will hopefully be deprecated as Rust evolves and doesn't offer enough
// advantages in the modern day to be worth the hassle -- Kayaba
pub trait Curve: Clone + Copy + PartialEq + Eq + Debug {
  /// Scalar field element type
  // This is available via G::Scalar yet `C::G::Scalar` is ambiguous, forcing horrific accesses
  type F: PrimeField;
  /// Group element type
  type G: Group<Scalar = Self::F> + GroupOps + PrimeGroup;
  /// Precomputed table type
  type T: Mul<Self::F, Output = Self::G>;

  /// ID for this curve
  const ID: &'static [u8];

  /// Generator for the group
  // While group does provide this in its API, privacy coins will want to use a custom basepoint
  const GENERATOR: Self::G;

  /// Table for the generator for the group
  /// If there isn't a precomputed table available, the generator itself should be used
  const GENERATOR_TABLE: Self::T;

  /// If little endian is used for the scalar field's Repr
  const LITTLE_ENDIAN: bool;

  /// Securely generate a random nonce. H4 from the IETF draft
  fn random_nonce<R: RngCore + CryptoRng>(secret: Self::F, rng: &mut R) -> Self::F;

  /// Hash the message for the binding factor. H3 from the IETF draft
  // This doesn't actually need to be part of Curve as it does nothing with the curve
  // This also solely relates to FROST and with a proper Algorithm/HRAM, all projects using
  // aggregatable signatures over this curve will work without issue
  // It is kept here as Curve + H{1, 2, 3} is effectively a ciphersuite according to the IETF draft
  // and moving it to Schnorr would force all of them into being ciphersuite-specific
  // H2 is left to the Schnorr Algorithm as H2 is the H used in HRAM, which Schnorr further
  // modularizes
  fn hash_msg(msg: &[u8]) -> Vec<u8>;

  /// Hash the commitments and message to calculate the binding factor. H1 from the IETF draft
  fn hash_binding_factor(binding: &[u8]) -> Self::F;

  // The following methods would optimally be F:: and G:: yet developers can't control F/G
  // They can control a trait they pass into this library

  /// Field element from hash. Used during key gen and by other crates under Serai as a general
  /// utility
  // Not parameterized by Digest as it's fine for it to use its own hash function as relevant to
  // hash_msg and hash_binding_factor
  #[allow(non_snake_case)]
  fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F;

  /// Constant size of a serialized scalar field element
  // The alternative way to grab this would be either serializing a junk element and getting its
  // length or doing a naive division of its BITS property by 8 and assuming a lack of padding
  #[allow(non_snake_case)]
  fn F_len() -> usize;

  /// Constant size of a serialized group element
  // We could grab the serialization as described above yet a naive developer may use a
  // non-constant size encoding, proving yet another reason to force this to be a provided constant
  // A naive developer could still provide a constant for a variable length encoding, yet at least
  // that is on them
  #[allow(non_snake_case)]
  fn G_len() -> usize;
}

/// Field element from slice
#[allow(non_snake_case)]
pub(crate) fn F_from_slice<F: PrimeField>(slice: &[u8]) -> Result<F, CurveError> {
  let mut encoding = F::Repr::default();
  encoding.as_mut().copy_from_slice(slice);

  let point = Option::<F>::from(F::from_repr(encoding)).ok_or(CurveError::InvalidScalar)?;
  if point.to_repr().as_ref() != slice {
    Err(CurveError::InvalidScalar)?;
  }
  Ok(point)
}

/// Group element from slice
#[allow(non_snake_case)]
pub(crate) fn G_from_slice<G: PrimeGroup>(slice: &[u8]) -> Result<G, CurveError> {
  let mut encoding = G::Repr::default();
  encoding.as_mut().copy_from_slice(slice);

  let point = Option::<G>::from(G::from_bytes(&encoding)).ok_or(CurveError::InvalidPoint)?;
  // Ban the identity, per the FROST spec, and non-canonical points
  if (point.is_identity().into()) || (point.to_bytes().as_ref() != slice) {
    Err(CurveError::InvalidPoint)?;
  }
  Ok(point)
}
