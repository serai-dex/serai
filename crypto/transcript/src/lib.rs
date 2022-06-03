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

#[derive(Clone, Debug)]
pub struct DigestTranscript<D: Digest>(Vec<u8>, PhantomData<D>);

impl<D: Digest> PartialEq for DigestTranscript<D> {
  fn eq(&self, other: &DigestTranscript<D>) -> bool {
    self.0 == other.0
  }
}

impl<D: Digest> DigestTranscript<D> {
  pub fn new(label: &'static [u8]) -> Self {
    DigestTranscript(label.to_vec(), PhantomData)
  }
}

impl<D: Digest> Transcript for DigestTranscript<D> {
  fn domain_separate(&mut self, label: &[u8]) {
    self.append_message(b"domain", label);
  }

  fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
    self.0.extend(label);
    // Assumes messages don't exceed 16 exabytes
    self.0.extend(u64::try_from(message.len()).unwrap().to_le_bytes());
    self.0.extend(message);
  }

  fn challenge(&mut self, label: &'static [u8]) -> Vec<u8> {
    self.0.extend(label);
    D::new().chain_update(&self.0).finalize().to_vec()
  }

  fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32] {
    let mut seed = [0; 32];
    seed.copy_from_slice(&self.challenge(label)[0 .. 32]);
    seed
  }
}
