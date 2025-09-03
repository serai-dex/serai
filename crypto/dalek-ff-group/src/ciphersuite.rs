use zeroize::Zeroize;

use sha2::Sha512;
use blake2::Blake2b512;

use ::ciphersuite::{group::Group, *};

use crate::*;

/// Ciphersuite for Ristretto.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Ristretto;
impl WrappedGroup for Ristretto {
  type F = Scalar;
  type G = RistrettoPoint;
  fn generator() -> Self::G {
    <RistrettoPoint as Group>::generator()
  }
}
impl Id for Ristretto {
  const ID: &[u8] = b"ristretto";
}
impl WithPreferredHash for Ristretto {
  type H = Blake2b512;
}
impl GroupCanonicalEncoding for Ristretto {
  fn from_canonical_bytes(bytes: &<Self::G as GroupEncoding>::Repr) -> CtOption<Self::G> {
    Self::G::from_bytes(bytes)
  }
}

/// Ciphersuite for Ed25519.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct Ed25519;
impl WrappedGroup for Ed25519 {
  type F = Scalar;
  type G = EdwardsPoint;
  fn generator() -> Self::G {
    <EdwardsPoint as Group>::generator()
  }
}
impl Id for Ed25519 {
  const ID: &[u8] = b"ed25519";
}
impl WithPreferredHash for Ed25519 {
  type H = Sha512;
}
impl GroupCanonicalEncoding for Ed25519 {}
