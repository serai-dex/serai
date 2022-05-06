use core::{marker::PhantomData, fmt::Debug};

#[cfg(features = "merlin")]
mod merlin;
#[cfg(features = "merlin")]
pub use merlin::MerlinTranscript;

use digest::Digest;

pub trait Transcript {
  fn domain_separate(&mut self, label: &[u8]);
  fn append_message(&mut self, label: &'static [u8], message: &[u8]);
  fn challenge(&mut self, label: &'static [u8]) -> Vec<u8>;
  fn rng_seed(&mut self, label: &'static [u8], additional_entropy: Option<[u8; 32]>) -> [u8; 32];
}

#[derive(Clone, Debug)]
pub struct DigestTranscript<D: Digest>(Vec<u8>, PhantomData<D>);

impl<D: Digest> DigestTranscript<D> {
  pub fn new(label: Vec<u8>) -> Self {
    DigestTranscript(label, PhantomData)
  }
}

impl<D: Digest> Transcript for DigestTranscript<D> {
  // It may be beneficial for each domain to be a nested transcript which is itself length prefixed
  // This would go further than Merlin though and require an accurate end_domain function which has
  // frustrations not worth bothering with when this shouldn't actually be meaningful
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

  fn rng_seed(&mut self, label: &'static [u8], additional_entropy: Option<[u8; 32]>) -> [u8; 32] {
    if additional_entropy.is_some() {
      self.append_message(b"additional_entropy", &additional_entropy.unwrap());
    }

    let mut seed = [0; 32];
    seed.copy_from_slice(&self.challenge(label)[0 .. 32]);
    seed
  }
}
