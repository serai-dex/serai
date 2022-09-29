#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![no_std]

#[cfg(feature = "merlin")]
mod merlin;
#[cfg(feature = "merlin")]
pub use crate::merlin::MerlinTranscript;

use digest::{typenum::type_operators::IsGreaterOrEqual, consts::U256, Digest, Output, HashMarker};

pub trait Transcript {
  type Challenge: Clone + Send + Sync + AsRef<[u8]>;

  /// Create a new transcript with the specified name.
  fn new(name: &'static [u8]) -> Self;

  /// Apply a domain separator to the transcript.
  fn domain_separate(&mut self, label: &'static [u8]);

  /// Append a message to the transcript.
  fn append_message(&mut self, label: &'static [u8], message: &[u8]);

  /// Produce a challenge. This MUST update the transcript as it does so, preventing the same
  /// challenge from being generated multiple times.
  fn challenge(&mut self, label: &'static [u8]) -> Self::Challenge;

  /// Produce a RNG seed. Helper function for parties needing to generate random data from an
  /// agreed upon state. Internally calls the challenge function for the needed bytes, converting
  /// them to the seed format rand_core expects.
  fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32];
}

enum DigestTranscriptMember {
  Name,
  Domain,
  Label,
  Value,
  Challenge,
}

impl DigestTranscriptMember {
  fn as_u8(&self) -> u8 {
    match self {
      DigestTranscriptMember::Name => 0,
      DigestTranscriptMember::Domain => 1,
      DigestTranscriptMember::Label => 2,
      DigestTranscriptMember::Value => 3,
      DigestTranscriptMember::Challenge => 4,
    }
  }
}

/// A trait defining cryptographic Digests with at least a 256-byte output size, assuming at least
/// a 128-bit level of security accordingly.
pub trait SecureDigest: Digest + HashMarker {}
impl<D: Digest + HashMarker> SecureDigest for D where D::OutputSize: IsGreaterOrEqual<U256> {}

/// A simple transcript format constructed around the specified hash algorithm.
#[derive(Clone, Debug)]
pub struct DigestTranscript<D: Clone + SecureDigest>(D);

impl<D: Clone + SecureDigest> DigestTranscript<D> {
  fn append(&mut self, kind: DigestTranscriptMember, value: &[u8]) {
    self.0.update([kind.as_u8()]);
    // Assumes messages don't exceed 16 exabytes
    self.0.update(u64::try_from(value.len()).unwrap().to_le_bytes());
    self.0.update(value);
  }
}

impl<D: Clone + SecureDigest> Transcript for DigestTranscript<D> {
  type Challenge = Output<D>;

  fn new(name: &'static [u8]) -> Self {
    let mut res = DigestTranscript(D::new());
    res.append(DigestTranscriptMember::Name, name);
    res
  }

  fn domain_separate(&mut self, label: &[u8]) {
    self.append(DigestTranscriptMember::Domain, label);
  }

  fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
    self.append(DigestTranscriptMember::Label, label);
    self.append(DigestTranscriptMember::Value, message);
  }

  fn challenge(&mut self, label: &'static [u8]) -> Self::Challenge {
    self.append(DigestTranscriptMember::Challenge, label);
    self.0.clone().finalize()
  }

  fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32] {
    let mut seed = [0; 32];
    seed.copy_from_slice(&self.challenge(label)[.. 32]);
    seed
  }
}

#[cfg(feature = "recommended")]
pub type RecommendedTranscript = DigestTranscript<blake2::Blake2b512>;
