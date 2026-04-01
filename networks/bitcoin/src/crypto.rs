use core::fmt::Debug;
use std_shims::{prelude::*, io};

use subtle::ConditionallySelectable as _;
use zeroize::Zeroizing;
use rand_core::{RngCore, CryptoRng};

use k256::{
  elliptic_curve::{
    ops::Reduce as _, group::prime::PrimeCurveAffine as _, point::AffineCoordinates as _,
  },
  U256, Scalar, ProjectivePoint,
};

use bitcoin::hashes::{HashEngine as _, Hash as _, sha256::Hash as Sha256};

use frost::{
  curve::{WrappedGroup, Secp256k1},
  Participant, ThresholdKeys, ThresholdView, FrostError,
  algorithm::{Hram as HramTrait, Algorithm, IetfSchnorr as FrostSchnorr},
};

/// Get the `x` coordinate of a non-infinity point.
///
/// Panics if the point is the point at infinity.
fn x(point: &ProjectivePoint) -> [u8; 32] {
  let point = point.to_affine();
  assert!(!bool::from(point.is_identity()));
  point.x().into()
}

/// A somewhat-BIP-340-compatible HRAm for use with [`modular_frost::algorithm::Schnorr`].
///
/// This will transcript the `x` coordinates of the nonce commitment, public key, but not their
/// `y` coordinates (as per BIP-340).
///
/// If the `y` coordinates of `R, A` have different parities, the returned challenge will NOT be
/// the BIP-340-defined challenge but its negative.
///
/// If either `R` or `A` is the point at infinity, this may panic.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Hram;
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
    <_>::conditional_select(&c, &-c, R.to_affine().y_is_odd() ^ A.to_affine().y_is_odd())
  }
}

/// BIP-340 Schnorr signature algorithm.
///
/// This will sign for the Taproot public key represented by the `x` coordinate of the group key.
///
/// This may panic if called with nonces/a group key which are the point at infinity (which have
/// a negligible probability for a well-reasoned caller, even with malicious participants
/// present).
///
/// The functions within this `Algorithm` are intended to be called per the timeline and structure
/// provided by the various machines within [`modular-frost`]. These functions may panic if called
/// in any other context or by any other method. No safety guarantees are provided if called
/// directly.
#[derive(Clone)]
pub(crate) struct Schnorr(FrostSchnorr<Secp256k1, Hram>);
impl Schnorr {
  /// Construct a Schnorr algorithm continuing the specified transcript.
  pub(crate) fn new() -> Schnorr {
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

  // Because FROST rejects nonce commitments which are the identity point, these nonce commitments
  // won't be the identity point except with negligible probability
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
      /*
        If $R.y \cong A.y \mod 2$, then the challenge will have been the BIP-340 challenge.

        If $R.y, A.y$ are even, the signature will be valid as-is.

        If $R.y$ is even but $A.y$ is odd, the private key will need to be negated, but the
        challenge would have been, so the signature is valid as-is.

        If $R.y$ is odd but $A.y$ is even, we will have `r - c x` when we want `(-r) + c x`. We
        can achieve this by negating the `s` value.

        If $R.y, A.y$ are odd, we will have `r + c x` when we want `(-r) - c x`, which we can again
        achieve by negating the `s` value.

        This summarizes as we need to negate `s` if `R.y` is odd.
      */
      sig.s = <_>::conditional_select(&sum, &-sum, sig.R.to_affine().y_is_odd());
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

#[test]
fn algorithm() {
  use core::str::FromStr as _;
  use rand_core::OsRng;
  use bitcoin::{
    key::{XOnlyPublicKey, Secp256k1 as Context},
    TapSighash,
  };
  use frost::tests::{algorithm_machines, key_gen, sign};

  let secp256k1 = Context::verification_only();

  for tweak_keys in [false, true] {
    for _ in 0 .. 100 {
      let mut keys = key_gen::<_, Secp256k1>(&mut OsRng);
      const MESSAGE: &[u8] = b"Hello, World!";

      // Tweaking keys is not strictly required, as this will sign for the key represented by the
      // `x` coordinate regardless of these keys' `y` coordinate
      if tweak_keys {
        for keys in keys.values_mut() {
          *keys = crate::wallet::tweak_keys(keys.clone());
        }
      }
      let group_key = keys[&Participant::new(1).unwrap()].group_key();

      let algo = Schnorr::new();
      let sig = sign(
        &mut OsRng,
        &algo,
        keys.clone(),
        algorithm_machines(&mut OsRng, &algo, &keys),
        TapSighash::hash(MESSAGE).as_ref(),
      );

      let () = XOnlyPublicKey::from_slice(&x(&group_key))
        .unwrap()
        .verify(
          &secp256k1,
          &TapSighash::hash(MESSAGE).into(),
          &<_>::from_str(&hex::encode(sig))
            .expect("couldn't convert produced signature to `secp256k1::Signature`"),
        )
        .unwrap();
    }
  }
}
