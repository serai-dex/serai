use core::{marker::PhantomData, fmt::Debug};

#[cfg(features = "merlin")]
mod merlin;
#[cfg(features = "merlin")]
pub use merlin::MerlinTranscript;

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use digest::Digest;

pub trait Transcript {
  type SeededRng: RngCore + CryptoRng;

  fn new(label: &'static [u8]) -> Self;
  fn append_message(&mut self, label: &'static [u8], message: &[u8]);
  fn challenge(&mut self, label: &'static [u8], len: usize) -> Vec<u8>;
  fn seeded_rng(&self, label: &'static [u8], additional_entropy: Option<[u8; 32]>) -> Self::SeededRng;
}

#[derive(Clone, Debug)]
pub struct DigestTranscript<D: Digest>(Vec<u8>, PhantomData<D>);
impl<D: Digest> Transcript for DigestTranscript<D> {
  // Uses ChaCha12 as even ChaCha8 should be secure yet 12 is considered a sane middleground
  type SeededRng = ChaCha12Rng;

  fn new(label: &'static [u8]) -> Self {
    DigestTranscript(label.to_vec(), PhantomData)
  }

  fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
    self.0.extend(label);
    // Assumes messages don't exceed 16 exabytes
    self.0.extend(u64::try_from(message.len()).unwrap().to_le_bytes());
    self.0.extend(message);
  }

  fn challenge(&mut self, label: &'static [u8], len: usize) -> Vec<u8> {
    self.0.extend(label);

    let mut challenge = Vec::with_capacity(len);
    challenge.extend(&D::new().chain_update(&self.0).chain_update(&0u64.to_le_bytes()).finalize());
    for i in 0 .. (len / challenge.len()) {
      challenge.extend(&D::new().chain_update(&self.0).chain_update(&u64::try_from(i).unwrap().to_le_bytes()).finalize());
    }
    challenge.truncate(len);
    challenge
  }

  fn seeded_rng(&self, label: &'static [u8], additional_entropy: Option<[u8; 32]>) -> Self::SeededRng {
    let mut transcript = DigestTranscript::<D>(self.0.clone(), PhantomData);
    if additional_entropy.is_some() {
      transcript.append_message(b"additional_entropy", &additional_entropy.unwrap());
    }
    transcript.0.extend(label);

    let mut seed = [0; 32];
    seed.copy_from_slice(&D::digest(&transcript.0)[0 .. 32]);
    ChaCha12Rng::from_seed(seed)
  }
}
