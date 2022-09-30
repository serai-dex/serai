use core::fmt::Debug;
use std::io::Read;

use thiserror::Error;

use rand_core::{RngCore, CryptoRng};

use zeroize::Zeroize;

use ff::{PrimeField, PrimeFieldBits};
use group::{Group, GroupOps, GroupEncoding, prime::PrimeGroup};

#[cfg(any(test, feature = "dalek"))]
mod dalek;
#[cfg(any(test, feature = "ristretto"))]
pub use dalek::{Ristretto, IetfRistrettoHram};
#[cfg(feature = "ed25519")]
pub use dalek::{Ed25519, IetfEd25519Hram};

#[cfg(feature = "kp256")]
mod kp256;
#[cfg(feature = "secp256k1")]
pub use kp256::{Secp256k1, IetfSecp256k1Hram};
#[cfg(feature = "p256")]
pub use kp256::{P256, IetfP256Hram};

#[cfg(feature = "ed448")]
mod ed448;
#[cfg(feature = "ed448")]
pub use ed448::{Ed448, Ietf8032Ed448Hram, NonIetfEd448Hram};

/// Set of errors for curve-related operations, namely encoding and decoding.
#[derive(Clone, Error, Debug)]
pub enum CurveError {
  #[error("invalid scalar")]
  InvalidScalar,
  #[error("invalid point")]
  InvalidPoint,
}

/// Unified trait to manage an elliptic curve.
// This should be moved into its own crate if the need for generic cryptography over ff/group
// continues, which is the exact reason ff/group exists (to provide a generic interface)
// elliptic-curve exists, yet it doesn't really serve the same role, nor does it use &[u8]/Vec<u8>
// It uses GenericArray which will hopefully be deprecated as Rust evolves and doesn't offer enough
// advantages in the modern day to be worth the hassle -- Kayaba
pub trait Curve: Clone + Copy + PartialEq + Eq + Debug + Zeroize {
  /// Scalar field element type.
  // This is available via G::Scalar yet `C::G::Scalar` is ambiguous, forcing horrific accesses
  type F: PrimeField + PrimeFieldBits + Zeroize;
  /// Group element type.
  type G: Group<Scalar = Self::F> + GroupOps + PrimeGroup + Zeroize;

  /// ID for this curve.
  const ID: &'static [u8];

  /// Generator for the group.
  // While group does provide this in its API, privacy coins may want to use a custom basepoint
  fn generator() -> Self::G;

  /// Hash the given dst and data to a byte vector. Used to instantiate H4 and H5.
  fn hash_to_vec(dst: &[u8], data: &[u8]) -> Vec<u8>;

  /// Field element from hash. Used during key gen and by other crates under Serai as a general
  /// utility. Used to instantiate H1 and H3.
  #[allow(non_snake_case)]
  fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F;

  /// Hash the message for the binding factor. H4 from the IETF draft.
  fn hash_msg(msg: &[u8]) -> Vec<u8> {
    Self::hash_to_vec(b"msg", msg)
  }

  /// Hash the commitments for the binding factor. H5 from the IETF draft.
  fn hash_commitments(commitments: &[u8]) -> Vec<u8> {
    Self::hash_to_vec(b"com", commitments)
  }

  /// Hash the commitments and message to calculate the binding factor. H1 from the IETF draft.
  fn hash_binding_factor(binding: &[u8]) -> Self::F {
    Self::hash_to_F(b"rho", binding)
  }

  /// Securely generate a random nonce. H3 from the IETF draft.
  fn random_nonce<R: RngCore + CryptoRng>(mut secret: Self::F, rng: &mut R) -> Self::F {
    let mut seed = vec![0; 32];
    rng.fill_bytes(&mut seed);

    let mut repr = secret.to_repr();
    secret.zeroize();

    seed.extend(repr.as_ref());
    for i in repr.as_mut() {
      i.zeroize();
    }

    let res = Self::hash_to_F(b"nonce", &seed);
    seed.zeroize();
    res
  }

  #[allow(non_snake_case)]
  fn F_len() -> usize {
    <Self::F as PrimeField>::Repr::default().as_ref().len()
  }

  #[allow(non_snake_case)]
  fn G_len() -> usize {
    <Self::G as GroupEncoding>::Repr::default().as_ref().len()
  }

  #[allow(non_snake_case)]
  fn read_F<R: Read>(r: &mut R) -> Result<Self::F, CurveError> {
    let mut encoding = <Self::F as PrimeField>::Repr::default();
    r.read_exact(encoding.as_mut()).map_err(|_| CurveError::InvalidScalar)?;

    // ff mandates this is canonical
    let res =
      Option::<Self::F>::from(Self::F::from_repr(encoding)).ok_or(CurveError::InvalidScalar);
    for b in encoding.as_mut() {
      b.zeroize();
    }
    res
  }

  #[allow(non_snake_case)]
  fn read_G<R: Read>(r: &mut R) -> Result<Self::G, CurveError> {
    let mut encoding = <Self::G as GroupEncoding>::Repr::default();
    r.read_exact(encoding.as_mut()).map_err(|_| CurveError::InvalidPoint)?;

    let point =
      Option::<Self::G>::from(Self::G::from_bytes(&encoding)).ok_or(CurveError::InvalidPoint)?;
    // Ban the identity, per the FROST spec, and non-canonical points
    if (point.is_identity().into()) || (point.to_bytes().as_ref() != encoding.as_ref()) {
      Err(CurveError::InvalidPoint)?;
    }
    Ok(point)
  }
}
