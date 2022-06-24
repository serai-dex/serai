use core::{marker::PhantomData, fmt::Debug};

#[cfg(features = "merlin")]
mod merlin;
#[cfg(features = "merlin")]
pub use merlin::MerlinTranscript;

use digest::Digest;

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
pub struct DigestTranscript<D: Digest>(Vec<u8>, PhantomData<D>);

impl<D: Digest> PartialEq for DigestTranscript<D> {
  fn eq(&self, other: &DigestTranscript<D>) -> bool {
    self.0 == other.0
  }
}

impl<D: Digest> DigestTranscript<D> {
  fn append(&mut self, kind: DigestTranscriptMember, value: &[u8]) {
    self.0.push(kind.as_u8());
    // Assumes messages don't exceed 16 exabytes
    self.0.extend(u64::try_from(value.len()).unwrap().to_le_bytes());
    self.0.extend(value);
  }

  pub fn new(name: &'static [u8]) -> Self {
    let mut res = DigestTranscript(vec![], PhantomData);
    res.append(DigestTranscriptMember::Name, name);
    res
  }
}

impl<D: Digest> Transcript for DigestTranscript<D> {
  fn domain_separate(&mut self, label: &[u8]) {
    self.append(DigestTranscriptMember::Domain, label);
  }

  fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
    self.append(DigestTranscriptMember::Label, label);
    self.append(DigestTranscriptMember::Value, message);
  }

  fn challenge(&mut self, label: &'static [u8]) -> Vec<u8> {
    self.append(DigestTranscriptMember::Challenge, label);
    D::new().chain_update(&self.0).finalize().to_vec()
  }

  fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32] {
    let mut seed = [0; 32];
    seed.copy_from_slice(&self.challenge(label)[0 .. 32]);
    seed
  }
}
