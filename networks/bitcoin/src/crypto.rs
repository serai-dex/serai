use k256::{
  elliptic_curve::sec1::{Tag, ToEncodedPoint},
  ProjectivePoint,
};

use bitcoin::key::XOnlyPublicKey;

/// Get the x coordinate of a non-infinity, even point. Panics on invalid input.
pub fn x(key: &ProjectivePoint) -> [u8; 32] {
  let encoded = key.to_encoded_point(true);
  assert_eq!(encoded.tag(), Tag::CompressedEvenY, "x coordinate of odd key");
  (*encoded.x().expect("point at infinity")).into()
}

/// Convert a non-infinity even point to a XOnlyPublicKey. Panics on invalid input.
pub fn x_only(key: &ProjectivePoint) -> XOnlyPublicKey {
  XOnlyPublicKey::from_slice(&x(key)).expect("x_only was passed a point which was infinity or odd")
}

/// Make a point even by adding the generator until it is even.
///
/// Returns the even point and the amount of additions required.
#[cfg(any(feature = "std", feature = "hazmat"))]
pub fn make_even(mut key: ProjectivePoint) -> (ProjectivePoint, u64) {
  let mut c = 0;
  while key.to_encoded_point(true).tag() == Tag::CompressedOddY {
    key += ProjectivePoint::GENERATOR;
    c += 1;
  }
  (key, c)
}

#[cfg(feature = "std")]
mod frost_crypto {
  use core::fmt::Debug;
  use std_shims::{vec::Vec, io};

  use zeroize::Zeroizing;
  use rand_core::{RngCore, CryptoRng};

  use bitcoin::hashes::{HashEngine, Hash, sha256::Hash as Sha256};

  use transcript::Transcript;

  use k256::{elliptic_curve::ops::Reduce, U256, Scalar};

  use frost::{
    curve::{Ciphersuite, Secp256k1},
    Participant, ThresholdKeys, ThresholdView, FrostError,
    algorithm::{Hram as HramTrait, Algorithm, Schnorr as FrostSchnorr},
  };

  use super::*;

  /// A BIP-340 compatible HRAm for use with the modular-frost Schnorr Algorithm.
  ///
  /// If passed an odd nonce, it will have the generator added until it is even.
  ///
  /// If the key is odd, this will panic.
  #[derive(Clone, Copy, Debug)]
  pub struct Hram;
  #[allow(non_snake_case)]
  impl HramTrait<Secp256k1> for Hram {
    fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
      // Convert the nonce to be even
      let (R, _) = make_even(*R);

      const TAG_HASH: Sha256 = Sha256::const_hash(b"BIP0340/challenge");

      let mut data = Sha256::engine();
      data.input(TAG_HASH.as_ref());
      data.input(TAG_HASH.as_ref());
      data.input(&x(&R));
      data.input(&x(A));
      data.input(m);

      Scalar::reduce(U256::from_be_slice(Sha256::from_engine(data).as_ref()))
    }
  }

  /// BIP-340 Schnorr signature algorithm.
  ///
  /// This must be used with a ThresholdKeys whose group key is even. If it is odd, this will panic.
  #[derive(Clone)]
  pub struct Schnorr<T: Sync + Clone + Debug + Transcript>(FrostSchnorr<Secp256k1, T, Hram>);
  impl<T: Sync + Clone + Debug + Transcript> Schnorr<T> {
    /// Construct a Schnorr algorithm continuing the specified transcript.
    pub fn new(transcript: T) -> Schnorr<T> {
      Schnorr(FrostSchnorr::new(transcript))
    }
  }

  impl<T: Sync + Clone + Debug + Transcript> Algorithm<Secp256k1> for Schnorr<T> {
    type Transcript = T;
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
      self.0.preprocess_addendum(rng, keys)
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
      nonce_sums: &[Vec<<Secp256k1 as Ciphersuite>::G>],
      nonces: Vec<Zeroizing<<Secp256k1 as Ciphersuite>::F>>,
      msg: &[u8],
    ) -> <Secp256k1 as Ciphersuite>::F {
      self.0.sign_share(params, nonce_sums, nonces, msg)
    }

    #[must_use]
    fn verify(
      &self,
      group_key: ProjectivePoint,
      nonces: &[Vec<ProjectivePoint>],
      sum: Scalar,
    ) -> Option<Self::Signature> {
      self.0.verify(group_key, nonces, sum).map(|mut sig| {
        // Make the R of the final signature even
        let offset;
        (sig.R, offset) = make_even(sig.R);
        // s = r + cx. Since we added to the r, add to s
        sig.s += Scalar::from(offset);
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
}
#[cfg(feature = "std")]
pub use frost_crypto::*;
