use core::{marker::PhantomData, fmt::{Debug, Formatter}};

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use digest::Digest;

#[derive(Clone)]
pub struct MerlinTranscript(merlin::Transcript);
// Merlin doesn't implement Debug so provide a stub which won't panic
impl Debug for MerlinTranscript {
  fn fmt(&self, _: &mut Formatter<'_>) -> Result<(), std::fmt::Error> { Ok(()) }
}

impl Transcript for MerlinTranscript {
  type SeededRng = ChaCha12Rng;

  fn new(label: &'static [u8]) -> Self {
    MerlinTranscript(merlin::Transcript::new(label))
  }

  fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
    self.0.append_message(label, message);
  }

  fn challenge(&mut self, label: &'static [u8], len: usize) -> Vec<u8> {
    let mut challenge = vec![];
    challenge.resize(len, 0);
    self.0.challenge_bytes(label, &mut challenge);
    challenge
  }

  fn seeded_rng(&self, label: &'static [u8], additional_entropy: Option<[u8; 32]>) -> ChaCha12Rng {
    let mut transcript = self.0.clone();
    if additional_entropy.is_some() {
      transcript.append_message(b"additional_entropy", &additional_entropy.unwrap());
    }
    let mut seed = [0; 32];
    transcript.challenge_bytes(label, &mut seed);
    ChaCha12Rng::from_seed(seed)
  }
}
