use core::fmt::Debug;

#[cfg(features = "merlin")]
mod merlin;
#[cfg(features = "merlin")]
pub use merlin::MerlinTranscript;

use digest::{typenum::type_operators::IsGreaterOrEqual, consts::U256, Digest};

pub trait Transcript {
  fn domain_separate(&mut self, label: &'static [u8]);
  fn append_message(&mut self, label: &'static [u8], message: &[u8]);
  fn challenge(&mut self, label: &'static [u8]) -> Vec<u8>;
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

#[derive(Clone, Debug)]
pub struct DigestTranscript<D: Clone + Digest>(D) where D::OutputSize: IsGreaterOrEqual<U256>;

impl<D: Clone + Digest> DigestTranscript<D> where D::OutputSize: IsGreaterOrEqual<U256> {
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

impl<D: Digest + Clone> Transcript for DigestTranscript<D>
  where D::OutputSize: IsGreaterOrEqual<U256> {
  fn domain_separate(&mut self, label: &[u8]) {
    self.append(DigestTranscriptMember::Domain, label);
  }

  fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
    self.append(DigestTranscriptMember::Label, label);
    self.append(DigestTranscriptMember::Value, message);
  }

  fn challenge(&mut self, label: &'static [u8]) -> Vec<u8> {
    self.append(DigestTranscriptMember::Challenge, label);
    self.0.clone().finalize().to_vec()
  }

  fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32] {
    let mut seed = [0; 32];
    seed.copy_from_slice(&self.challenge(label)[0 .. 32]);
    seed
  }
}
