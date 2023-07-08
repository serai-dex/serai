use core::{marker::PhantomData, fmt::Debug};
use std::io::{self, Read, Write};

use zeroize::Zeroizing;
use rand_core::{RngCore, CryptoRng};

use transcript::Transcript;

use crate::{Participant, ThresholdKeys, ThresholdView, Curve, FrostError};
pub use schnorr::SchnorrSignature;

/// Write an addendum to a writer.
pub trait WriteAddendum {
  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()>;
}

impl WriteAddendum for () {
  fn write<W: Write>(&self, _: &mut W) -> io::Result<()> {
    Ok(())
  }
}

/// Trait alias for the requirements to be used as an addendum.
pub trait Addendum: Send + Sync + Clone + PartialEq + Debug + WriteAddendum {}
impl<A: Send + Sync + Clone + PartialEq + Debug + WriteAddendum> Addendum for A {}

/// Algorithm trait usable by the FROST signing machine to produce signatures..
pub trait Algorithm<C: Curve>: Send + Sync + Clone {
  /// The transcript format this algorithm uses. This likely should NOT be the IETF-compatible
  /// transcript included in this crate.
  type Transcript: Sync + Clone + Debug + Transcript;
  /// Serializable addendum, used in algorithms requiring more data than just the nonces.
  type Addendum: Addendum;
  /// The resulting type of the signatures this algorithm will produce.
  type Signature: Clone + PartialEq + Debug;

  /// Obtain a mutable borrow of the underlying transcript.
  fn transcript(&mut self) -> &mut Self::Transcript;

  /// Obtain the list of nonces to generate, as specified by the generators to create commitments
  /// against per-nonce.
  fn nonces(&self) -> Vec<Vec<C::G>>;

  /// Generate an addendum to FROST"s preprocessing stage.
  fn preprocess_addendum<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    keys: &ThresholdKeys<C>,
  ) -> Self::Addendum;

  /// Read an addendum from a reader.
  fn read_addendum<R: Read>(&self, reader: &mut R) -> io::Result<Self::Addendum>;

  /// Proccess the addendum for the specified participant. Guaranteed to be called in order.
  fn process_addendum(
    &mut self,
    params: &ThresholdView<C>,
    l: Participant,
    reader: Self::Addendum,
  ) -> Result<(), FrostError>;

  /// Sign a share with the given secret/nonce.
  /// The secret will already have been its lagrange coefficient applied so it is the necessary
  /// key share.
  /// The nonce will already have been processed into the combined form d + (e * p).
  fn sign_share(
    &mut self,
    params: &ThresholdView<C>,
    nonce_sums: &[Vec<C::G>],
    nonces: Vec<Zeroizing<C::F>>,
    msg: &[u8],
  ) -> C::F;

  /// Verify a signature.
  #[must_use]
  fn verify(&self, group_key: C::G, nonces: &[Vec<C::G>], sum: C::F) -> Option<Self::Signature>;

  /// Verify a specific share given as a response.
  /// This function should return a series of pairs whose products should sum to zero for a valid
  /// share. Any error raised is treated as the share being invalid.
  #[allow(clippy::type_complexity, clippy::result_unit_err)]
  fn verify_share(
    &self,
    verification_share: C::G,
    nonces: &[Vec<C::G>],
    share: C::F,
  ) -> Result<Vec<(C::F, C::G)>, ()>;
}

mod sealed {
  pub use super::*;

  /// IETF-compliant transcript. This is incredibly naive and should not be used within larger
  /// protocols.
  #[derive(Clone, Debug)]
  pub struct IetfTranscript(pub(crate) Vec<u8>);
  impl Transcript for IetfTranscript {
    type Challenge = Vec<u8>;

    fn new(_: &'static [u8]) -> Self {
      Self(vec![])
    }

    fn domain_separate(&mut self, _: &[u8]) {}

    fn append_message<M: AsRef<[u8]>>(&mut self, _: &'static [u8], message: M) {
      self.0.extend(message.as_ref());
    }

    fn challenge(&mut self, _: &'static [u8]) -> Vec<u8> {
      self.0.clone()
    }

    // FROST won't use this and this shouldn't be used outside of FROST
    fn rng_seed(&mut self, _: &'static [u8]) -> [u8; 32] {
      unimplemented!()
    }
  }
}
pub(crate) use sealed::IetfTranscript;

/// HRAm usable by the included Schnorr signature algorithm to generate challenges.
pub trait Hram<C: Curve>: Send + Sync + Clone {
  /// HRAm function to generate a challenge.
  /// H2 from the IETF draft, despite having a different argument set (not being pre-formatted).
  #[allow(non_snake_case)]
  fn hram(R: &C::G, A: &C::G, m: &[u8]) -> C::F;
}

/// Schnorr signature algorithm ((R, s) where s = r + cx).
#[derive(Clone)]
pub struct Schnorr<C: Curve, T: Sync + Clone + Debug + Transcript, H: Hram<C>> {
  transcript: T,
  c: Option<C::F>,
  _hram: PhantomData<H>,
}

/// IETF-compliant Schnorr signature algorithm.
///
/// This algorithm specifically uses the transcript format defined in the FROST IETF draft.
/// It's a naive transcript format not viable for usage in larger protocols, yet is presented here
/// in order to provide compatibility.
///
/// Usage of this with key offsets will break the intended compatibility as the IETF draft does not
/// specify a protocol for offsets.
pub type IetfSchnorr<C, H> = Schnorr<C, IetfTranscript, H>;

impl<C: Curve, T: Sync + Clone + Debug + Transcript, H: Hram<C>> Schnorr<C, T, H> {
  /// Construct a Schnorr algorithm continuing the specified transcript.
  pub fn new(transcript: T) -> Self {
    Self { transcript, c: None, _hram: PhantomData }
  }
}

impl<C: Curve, H: Hram<C>> IetfSchnorr<C, H> {
  /// Construct a IETF-compatible Schnorr algorithm.
  ///
  /// Please see the `IetfSchnorr` documentation for the full details of this.
  pub fn ietf() -> Self {
    Self::new(IetfTranscript(vec![]))
  }
}

impl<C: Curve, T: Sync + Clone + Debug + Transcript, H: Hram<C>> Algorithm<C> for Schnorr<C, T, H> {
  type Transcript = T;
  type Addendum = ();
  type Signature = SchnorrSignature<C>;

  fn transcript(&mut self) -> &mut Self::Transcript {
    &mut self.transcript
  }

  fn nonces(&self) -> Vec<Vec<C::G>> {
    vec![vec![C::generator()]]
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(&mut self, _: &mut R, _: &ThresholdKeys<C>) {}

  fn read_addendum<R: Read>(&self, _: &mut R) -> io::Result<Self::Addendum> {
    Ok(())
  }

  fn process_addendum(
    &mut self,
    _: &ThresholdView<C>,
    _: Participant,
    _: (),
  ) -> Result<(), FrostError> {
    Ok(())
  }

  fn sign_share(
    &mut self,
    params: &ThresholdView<C>,
    nonce_sums: &[Vec<C::G>],
    mut nonces: Vec<Zeroizing<C::F>>,
    msg: &[u8],
  ) -> C::F {
    let c = H::hram(&nonce_sums[0][0], &params.group_key(), msg);
    self.c = Some(c);
    SchnorrSignature::<C>::sign(params.secret_share(), nonces.swap_remove(0), c).s
  }

  #[must_use]
  fn verify(&self, group_key: C::G, nonces: &[Vec<C::G>], sum: C::F) -> Option<Self::Signature> {
    let sig = SchnorrSignature { R: nonces[0][0], s: sum };
    Some(sig).filter(|sig| sig.verify(group_key, self.c.unwrap()))
  }

  fn verify_share(
    &self,
    verification_share: C::G,
    nonces: &[Vec<C::G>],
    share: C::F,
  ) -> Result<Vec<(C::F, C::G)>, ()> {
    Ok(
      SchnorrSignature::<C> { R: nonces[0][0], s: share }
        .batch_statements(verification_share, self.c.unwrap())
        .to_vec(),
    )
  }
}
