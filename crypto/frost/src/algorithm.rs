use core::{marker::PhantomData, fmt::Debug};
use std::io::Read;

use rand_core::{RngCore, CryptoRng};

use transcript::Transcript;

use crate::{Curve, FrostError, FrostView, schnorr};
pub use schnorr::SchnorrSignature;

/// Algorithm trait usable by the FROST signing machine to produce signatures..
pub trait Algorithm<C: Curve>: Clone {
  /// The transcript format this algorithm uses. This likely should NOT be the IETF-compatible
  /// transcript included in this crate.
  type Transcript: Transcript + Clone + Debug;
  /// The resulting type of the signatures this algorithm will produce.
  type Signature: Clone + PartialEq + Debug;

  /// Obtain a mutable borrow of the underlying transcript.
  fn transcript(&mut self) -> &mut Self::Transcript;

  /// Obtain the list of nonces to generate, as specified by the basepoints to create commitments.
  /// against per-nonce. These are not committed to by FROST on the underlying transcript.
  fn nonces(&self) -> Vec<Vec<C::G>>;

  /// Generate an addendum to FROST"s preprocessing stage.
  fn preprocess_addendum<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    params: &FrostView<C>,
  ) -> Vec<u8>;

  /// Proccess the addendum for the specified participant. Guaranteed to be ordered.
  fn process_addendum<Re: Read>(
    &mut self,
    params: &FrostView<C>,
    l: u16,
    reader: &mut Re,
  ) -> Result<(), FrostError>;

  /// Sign a share with the given secret/nonce.
  /// The secret will already have been its lagrange coefficient applied so it is the necessary
  /// key share.
  /// The nonce will already have been processed into the combined form d + (e * p).
  fn sign_share(
    &mut self,
    params: &FrostView<C>,
    nonce_sums: &[Vec<C::G>],
    nonces: &[C::F],
    msg: &[u8],
  ) -> C::F;

  /// Verify a signature.
  #[must_use]
  fn verify(&self, group_key: C::G, nonces: &[Vec<C::G>], sum: C::F) -> Option<Self::Signature>;

  /// Verify a specific share given as a response. Used to determine blame if signature
  /// verification fails.
  #[must_use]
  fn verify_share(&self, verification_share: C::G, nonces: &[Vec<C::G>], share: C::F) -> bool;
}

/// IETF-compliant transcript. This is incredibly naive and should not be used within larger
/// protocols.
#[derive(Clone, Debug)]
pub struct IetfTranscript(Vec<u8>);
impl Transcript for IetfTranscript {
  type Challenge = Vec<u8>;

  fn new(_: &'static [u8]) -> IetfTranscript {
    IetfTranscript(vec![])
  }

  fn domain_separate(&mut self, _: &[u8]) {}

  fn append_message(&mut self, _: &'static [u8], message: &[u8]) {
    self.0.extend(message);
  }

  fn challenge(&mut self, _: &'static [u8]) -> Vec<u8> {
    self.0.clone()
  }

  fn rng_seed(&mut self, _: &'static [u8]) -> [u8; 32] {
    unimplemented!()
  }
}

/// HRAm usable by the included Schnorr signature algorithm to generate challenges.
pub trait Hram<C: Curve>: Clone {
  /// HRAm function to generate a challenge.
  /// H2 from the IETF draft, despite having a different argument set (not being pre-formatted).
  #[allow(non_snake_case)]
  fn hram(R: &C::G, A: &C::G, m: &[u8]) -> C::F;
}

/// IETF-compliant Schnorr signature algorithm ((R, s) where s = r + cx).
#[derive(Clone)]
pub struct Schnorr<C: Curve, H: Hram<C>> {
  transcript: IetfTranscript,
  c: Option<C::F>,
  _hram: PhantomData<H>,
}

impl<C: Curve, H: Hram<C>> Default for Schnorr<C, H> {
  fn default() -> Self {
    Self::new()
  }
}

impl<C: Curve, H: Hram<C>> Schnorr<C, H> {
  pub fn new() -> Schnorr<C, H> {
    Schnorr { transcript: IetfTranscript(vec![]), c: None, _hram: PhantomData }
  }
}

impl<C: Curve, H: Hram<C>> Algorithm<C> for Schnorr<C, H> {
  type Transcript = IetfTranscript;
  type Signature = SchnorrSignature<C>;

  fn transcript(&mut self) -> &mut Self::Transcript {
    &mut self.transcript
  }

  fn nonces(&self) -> Vec<Vec<C::G>> {
    vec![vec![C::generator()]]
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    &mut self,
    _: &mut R,
    _: &FrostView<C>,
  ) -> Vec<u8> {
    vec![]
  }

  fn process_addendum<Re: Read>(
    &mut self,
    _: &FrostView<C>,
    _: u16,
    _: &mut Re,
  ) -> Result<(), FrostError> {
    Ok(())
  }

  fn sign_share(
    &mut self,
    params: &FrostView<C>,
    nonce_sums: &[Vec<C::G>],
    nonces: &[C::F],
    msg: &[u8],
  ) -> C::F {
    let c = H::hram(&nonce_sums[0][0], &params.group_key(), msg);
    self.c = Some(c);
    schnorr::sign::<C>(params.secret_share(), nonces[0], c).s
  }

  #[must_use]
  fn verify(&self, group_key: C::G, nonces: &[Vec<C::G>], sum: C::F) -> Option<Self::Signature> {
    let sig = SchnorrSignature { R: nonces[0][0], s: sum };
    if schnorr::verify::<C>(group_key, self.c.unwrap(), &sig) {
      Some(sig)
    } else {
      None
    }
  }

  #[must_use]
  fn verify_share(&self, verification_share: C::G, nonces: &[Vec<C::G>], share: C::F) -> bool {
    schnorr::verify::<C>(
      verification_share,
      self.c.unwrap(),
      &SchnorrSignature { R: nonces[0][0], s: share },
    )
  }
}
