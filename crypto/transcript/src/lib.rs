#![no_std]

#[cfg(feature = "merlin")]
mod merlin;
#[cfg(feature = "merlin")]
pub use crate::merlin::MerlinTranscript;

use digest::{typenum::type_operators::IsGreaterOrEqual, consts::U256, Digest, Output};

pub trait Transcript {
  type Challenge: Clone + Send + Sync + AsRef<[u8]>;

  fn domain_separate(&mut self, label: &'static [u8]);
  fn append_message(&mut self, label: &'static [u8], message: &[u8]);
  fn challenge(&mut self, label: &'static [u8]) -> Self::Challenge;
  fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32];
}

enum DigestTranscriptMember {
  Name,
  Domain,
  Label,
  Value,
  Challenge
}

impl DigestTranscriptMember {
  fn as_u8(&self) -> u8 {
    match self {
      DigestTranscriptMember::Name => 0,
      DigestTranscriptMember::Domain => 1,
      DigestTranscriptMember::Label => 2,
      DigestTranscriptMember::Value => 3,
      DigestTranscriptMember::Challenge => 4
    }
  }
}

pub trait SecureDigest: Clone + Digest {}
impl<D: Clone + Digest> SecureDigest for D where D::OutputSize: IsGreaterOrEqual<U256> {}

#[derive(Clone, Debug)]
pub struct DigestTranscript<D: SecureDigest>(D);

impl<D: SecureDigest> DigestTranscript<D> {
  fn append(&mut self, kind: DigestTranscriptMember, value: &[u8]) {
    self.0.update(&[kind.as_u8()]);
    // Assumes messages don't exceed 16 exabytes
    self.0.update(u64::try_from(value.len()).unwrap().to_le_bytes());
    self.0.update(value);
  }

  pub fn new(name: &'static [u8]) -> Self {
    let mut res = DigestTranscript(D::new());
    res.append(DigestTranscriptMember::Name, name);
    res
  }
}

impl<D: SecureDigest> Transcript for DigestTranscript<D> {
  type Challenge = Output<D>;

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
