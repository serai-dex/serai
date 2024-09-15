use subtle::Choice;
use group::ff::PrimeField;
use k256::{
  elliptic_curve::{
    ops::Reduce,
    point::{AffineCoordinates, DecompressPoint},
  },
  AffinePoint, ProjectivePoint, Scalar, U256 as KU256,
};

/// A public key for the Schnorr Solidity library.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PublicKey {
  A: ProjectivePoint,
  x_coordinate: [u8; 32],
}

impl PublicKey {
  /// Construct a new `PublicKey`.
  ///
  /// This will return None if the provided point isn't eligible to be a public key (due to
  /// bounds such as parity).
  #[must_use]
  pub fn new(A: ProjectivePoint) -> Option<PublicKey> {
    let affine = A.to_affine();

    // Only allow even keys to save a word within Ethereum
    if bool::from(affine.y_is_odd()) {
      None?;
    }

    let x_coordinate = affine.x();
    // Return None if the x-coordinate isn't mutual to both fields
    // While reductions shouldn't be an issue, it's one less headache/concern to have
    // The trivial amount of public keys this makes non-representable aren't a concern
    if <Scalar as Reduce<KU256>>::reduce_bytes(&x_coordinate).to_repr() != x_coordinate {
      None?;
    }

    let x_coordinate: [u8; 32] = x_coordinate.into();
    // Returns None if the x-coordinate is 0
    // Such keys will never have their signatures able to be verified
    if x_coordinate == [0; 32] {
      None?;
    }
    Some(PublicKey { A, x_coordinate })
  }

  /// The point for this public key.
  #[must_use]
  pub fn point(&self) -> ProjectivePoint {
    self.A
  }

  /// The Ethereum representation of this public key.
  #[must_use]
  pub fn eth_repr(&self) -> [u8; 32] {
    // We only encode the x-coordinate due to fixing the sign of the y-coordinate
    self.x_coordinate
  }

  /// Construct a PublicKey from its Ethereum representation.
  // This wouldn't be possible if the x-coordinate had been reduced
  #[must_use]
  pub fn from_eth_repr(repr: [u8; 32]) -> Option<Self> {
    let x_coordinate = repr;

    let y_is_odd = Choice::from(0);
    let A_affine =
      Option::<AffinePoint>::from(AffinePoint::decompress(&x_coordinate.into(), y_is_odd))?;
    let A = ProjectivePoint::from(A_affine);
    Some(PublicKey { A, x_coordinate })
  }
}
