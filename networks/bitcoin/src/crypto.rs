use core::fmt::Debug;
use std_shims::{prelude::*, io};

use subtle::{Choice, ConstantTimeEq as _, ConditionallySelectable as _};
use zeroize::Zeroizing;
use rand_core::{RngCore, CryptoRng};

use k256::{
  elliptic_curve::{ops::Reduce as _, sec1::ToEncodedPoint as _},
  U256, Scalar, ProjectivePoint,
};

use bitcoin::{
  hashes::{HashEngine as _, Hash as _, sha256::Hash as Sha256},
  key::XOnlyPublicKey,
};

use frost::{
  curve::{WrappedGroup, Secp256k1},
  Participant, ThresholdKeys, ThresholdView, FrostError,
  algorithm::{Hram as HramTrait, Algorithm, IetfSchnorr as FrostSchnorr},
};

/// Get the x coordinate of a non-infinity point.
///
/// Panics on invalid input.
fn x(key: &ProjectivePoint) -> [u8; 32] {
  let encoded = key.to_encoded_point(true);
  (*encoded.x().expect("point at infinity")).into()
}

/// Convert a non-infinity point to a XOnlyPublicKey (dropping its sign).
///
/// Panics on invalid input.
pub(crate) fn x_only(key: &ProjectivePoint) -> XOnlyPublicKey {
  XOnlyPublicKey::from_slice(&x(key)).expect("x_only was passed a point which was infinity or odd")
}

/// Return if a point must be negated to have an even Y coordinate and be eligible for use.
pub(crate) fn needs_negation(key: &ProjectivePoint) -> Choice {
  use k256::elliptic_curve::sec1::Tag;
  u8::from(key.to_encoded_point(true).tag()).ct_eq(&u8::from(Tag::CompressedOddY))
}

/// A BIP-340 compatible HRAm for use with the modular-frost Schnorr Algorithm.
///
/// If passed an odd nonce, the challenge will be negated.
///
/// If either `R` or `A` is the point at infinity, this will panic.
#[derive(Clone, Copy, Debug)]
pub struct Hram;
#[expect(non_snake_case)]
impl HramTrait<Secp256k1> for Hram {
  fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
    const TAG_HASH: Sha256 = Sha256::const_hash(b"BIP0340/challenge");

    let mut data = Sha256::engine();
    data.input(TAG_HASH.as_ref());
    data.input(TAG_HASH.as_ref());
    data.input(&x(R));
    data.input(&x(A));
    data.input(m);

    let c = Scalar::reduce(U256::from_be_slice(Sha256::from_engine(data).as_ref()));
    // If the nonce was odd, sign `r - cx` instead of `r + cx`, allowing us to negate `s` at the
    // end to sign as `-r + cx`
    <_>::conditional_select(&c, &-c, needs_negation(R))
  }
}

/// BIP-340 Schnorr signature algorithm.
///
/// This may panic if called with nonces/a group key which are the point at infinity (which have
/// a negligible probability for a well-reasoned caller, even with malicious participants
/// present).
///
/// `verify`, `verify_share` MUST be called after `sign_share` is called. Otherwise, this library
/// MAY panic.
#[derive(Clone)]
pub struct Schnorr(FrostSchnorr<Secp256k1, Hram>);
impl Schnorr {
  /// Construct a Schnorr algorithm continuing the specified transcript.
  #[expect(clippy::new_without_default)]
  pub fn new() -> Schnorr {
    Schnorr(FrostSchnorr::ietf())
  }
}

impl Algorithm<Secp256k1> for Schnorr {
  type Transcript = <FrostSchnorr<Secp256k1, Hram> as Algorithm<Secp256k1>>::Transcript;
  type Addendum = ();
  type Signature = [u8; 64];

  fn transcript(&mut self) -> &mut Self::Transcript {
    self.0.transcript()
  }

  fn nonces(&self) -> Vec<Vec<ProjectivePoint>> {
    self.0.nonces()
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    keys: &ThresholdKeys<Secp256k1>,
  ) {
    self.0.preprocess_addendum(rng, keys);
  }

  fn read_addendum<R: io::Read>(&self, reader: &mut R) -> io::Result<Self::Addendum> {
    self.0.read_addendum(reader)
  }

  fn process_addendum(
    &mut self,
    view: &ThresholdView<Secp256k1>,
    i: Participant,
    addendum: (),
  ) -> Result<(), FrostError> {
    self.0.process_addendum(view, i, addendum)
  }

  fn sign_share(
    &mut self,
    params: &ThresholdView<Secp256k1>,
    nonce_sums: &[Vec<<Secp256k1 as WrappedGroup>::G>],
    nonces: Vec<Zeroizing<<Secp256k1 as WrappedGroup>::F>>,
    msg: &[u8],
  ) -> <Secp256k1 as WrappedGroup>::F {
    self.0.sign_share(params, nonce_sums, nonces, msg)
  }

  fn verify(
    &self,
    group_key: ProjectivePoint,
    nonces: &[Vec<ProjectivePoint>],
    sum: Scalar,
  ) -> Option<Self::Signature> {
    self.0.verify(group_key, nonces, sum).map(|mut sig| {
      sig.s = <_>::conditional_select(&sum, &-sum, needs_negation(&sig.R));
      // Convert to a Bitcoin signature by dropping the byte for the point's sign bit
      sig.serialize()[1 ..].try_into().unwrap()
    })
  }

  fn verify_share(
    &self,
    verification_share: ProjectivePoint,
    nonces: &[Vec<ProjectivePoint>],
    share: Scalar,
  ) -> Result<Vec<(Scalar, ProjectivePoint)>, ()> {
    self.0.verify_share(verification_share, nonces, share)
  }
}
