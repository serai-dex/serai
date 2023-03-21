#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![no_std]

///! A transcript trait valid over a variety of transcript formats.

#[cfg(feature = "merlin")]
mod merlin;
#[cfg(feature = "merlin")]
pub use crate::merlin::MerlinTranscript;

/// Tests for a transcript.
#[cfg(any(test, feature = "tests"))]
pub mod tests;

use digest::{
  typenum::{
    consts::U32, marker_traits::NonZero, type_operators::IsGreaterOrEqual, operator_aliases::GrEq,
  },
  Digest, Output, HashMarker,
};

/// A transcript trait valid over a variety of transcript formats.
pub trait Transcript: Send + Clone {
  type Challenge: Send + Sync + Clone + AsRef<[u8]>;

  /// Create a new transcript with the specified name.
  fn new(name: &'static [u8]) -> Self;

  /// Apply a domain separator to the transcript.
  fn domain_separate(&mut self, label: &'static [u8]);

  /// Append a message to the transcript.
  fn append_message<M: AsRef<[u8]>>(&mut self, label: &'static [u8], message: M);

  /// Produce a challenge.
  ///
  /// Implementors MUST update the transcript as it does so, preventing the same challenge from
  /// being generated multiple times.
  fn challenge(&mut self, label: &'static [u8]) -> Self::Challenge;

  /// Produce a RNG seed.
  ///
  /// Helper function for parties needing to generate random data from an agreed upon state.
  ///
  /// Implementors MAY internally call the challenge function for the needed bytes, and accordingly
  /// produce a transcript conflict between two transcripts, one which called challenge(label) and
  /// one which called rng_seed(label) at the same point.
  fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32];
}

enum DigestTranscriptMember {
  Name,
  Domain,
  Label,
  Value,
  Challenge,
  Continued,
  Challenged,
}

impl DigestTranscriptMember {
  fn as_u8(&self) -> u8 {
    match self {
      DigestTranscriptMember::Name => 0,
      DigestTranscriptMember::Domain => 1,
      DigestTranscriptMember::Label => 2,
      DigestTranscriptMember::Value => 3,
      DigestTranscriptMember::Challenge => 4,
      DigestTranscriptMember::Continued => 5,
      DigestTranscriptMember::Challenged => 6,
    }
  }
}

/// A trait defining cryptographic Digests with at least a 256-bit output size, assuming at least a
/// 128-bit level of security accordingly.
pub trait SecureDigest: Digest + HashMarker {}
impl<D: Digest + HashMarker> SecureDigest for D
where
  // This just lets us perform the comparison
  D::OutputSize: IsGreaterOrEqual<U32>,
  // Perform the comparison and make sure it's true (not zero), meaning D::OutputSize is >= U32
  // This should be U32 as it's length in bytes, not bits
  GrEq<D::OutputSize, U32>: NonZero,
{
}

/// A simple transcript format constructed around the specified hash algorithm.
#[derive(Clone, Debug)]
pub struct DigestTranscript<D: Send + Clone + SecureDigest>(D);

impl<D: Send + Clone + SecureDigest> DigestTranscript<D> {
  fn append(&mut self, kind: DigestTranscriptMember, value: &[u8]) {
    self.0.update([kind.as_u8()]);
    // Assumes messages don't exceed 16 exabytes
    self.0.update(u64::try_from(value.len()).unwrap().to_le_bytes());
    self.0.update(value);
  }
}

impl<D: Send + Clone + SecureDigest> Transcript for DigestTranscript<D> {
  type Challenge = Output<D>;

  fn new(name: &'static [u8]) -> Self {
    let mut res = DigestTranscript(D::new());
    res.append(DigestTranscriptMember::Name, name);
    res
  }

  fn domain_separate(&mut self, label: &'static [u8]) {
    self.append(DigestTranscriptMember::Domain, label);
  }

  fn append_message<M: AsRef<[u8]>>(&mut self, label: &'static [u8], message: M) {
    self.append(DigestTranscriptMember::Label, label);
    self.append(DigestTranscriptMember::Value, message.as_ref());
  }

  fn challenge(&mut self, label: &'static [u8]) -> Self::Challenge {
    self.append(DigestTranscriptMember::Challenge, label);
    let mut cloned = self.0.clone();

    // Explicitly fork these transcripts to prevent length extension attacks from being possible
    // (at least, without the additional ability to remove a byte from a finalized hash)
    self.0.update([DigestTranscriptMember::Continued.as_u8()]);
    cloned.update([DigestTranscriptMember::Challenged.as_u8()]);
    cloned.finalize()
  }

  fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32] {
    let mut seed = [0; 32];
    seed.copy_from_slice(&self.challenge(label)[.. 32]);
    seed
  }
}

/// The recommended transcript, guaranteed to be secure against length-extension attacks.
#[cfg(feature = "recommended")]
pub type RecommendedTranscript = DigestTranscript<blake2::Blake2b512>;
