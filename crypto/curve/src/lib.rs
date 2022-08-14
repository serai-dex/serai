use core::fmt::Debug;
use std::io::Read;

use thiserror::Error;

use zeroize::Zeroize;

pub use group;
pub use group::ff;
use group::{ff::{PrimeField, PrimeFieldBits}, Group, GroupOps, GroupEncoding, prime::PrimeGroup};

/// Set of errors for curve-related operations, namely encoding and decoding
#[derive(Clone, Error, Debug)]
pub enum CurveError {
  #[error("invalid scalar")]
  InvalidScalar,
  #[error("invalid point")]
  InvalidPoint,
}

/// Curve trait ensuring access to a variety of ff/group APIs
pub trait Curve: Zeroize + Clone + Copy + PartialEq + Eq + Debug {
  /// Scalar field element type
  type F: Zeroize + PrimeField + PrimeFieldBits;
  /// Group element type
  type G: Zeroize + Group<Scalar = Self::F> + GroupOps + PrimeGroup;

  /// Generator for the group
  // While group does provide this in its API, multiple schemes frequently require a
  // different/variable one
  fn generator() -> Self::G;

  /// Length of a serialized Scalar field element
  #[allow(non_snake_case)]
  fn F_len() -> usize {
    <Self::F as PrimeField>::Repr::default().as_ref().len()
  }

  /// Length of a serialized group element
  #[allow(non_snake_case)]
  fn G_len() -> usize {
    <Self::G as GroupEncoding>::Repr::default().as_ref().len()
  }

  /// Read a canonical Scalar field element from a Reader
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

  /// Read a canonical, non-identity, group element from a Reader
  #[allow(non_snake_case)]
  fn read_G<R: Read>(r: &mut R) -> Result<Self::G, CurveError> {
    let mut encoding = <Self::G as GroupEncoding>::Repr::default();
    r.read_exact(encoding.as_mut()).map_err(|_| CurveError::InvalidPoint)?;

    let point =
      Option::<Self::G>::from(Self::G::from_bytes(&encoding)).ok_or(CurveError::InvalidPoint)?;

    if (point.is_identity().into()) || (point.to_bytes().as_ref() != encoding.as_ref()) {
      Err(CurveError::InvalidPoint)?;
    }

    Ok(point)
  }
}

impl<G: Zeroize + PrimeGroup> Curve for G where G::Scalar: Zeroize + PrimeField + PrimeFieldBits {
  type F = G::Scalar;
  type G = G;

  fn generator() -> G {
    G::generator()
  }
}

/// Curve implementing hash to curve for its field/group
pub trait HashToCurve: Curve {
  #[allow(non_snake_case)]
  fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F;
  #[allow(non_snake_case)]
  fn hash_to_G(dst: &[u8], msg: &[u8]) -> Self::G;
}
