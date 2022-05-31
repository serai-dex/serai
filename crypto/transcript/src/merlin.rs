use core::{marker::PhantomData, fmt::{Debug, Formatter}};

use digest::Digest;

#[derive(Clone, PartialEq)]
pub struct MerlinTranscript(pub merlin::Transcript);
// Merlin doesn't implement Debug so provide a stub which won't panic
impl Debug for MerlinTranscript {
  fn fmt(&self, _: &mut Formatter<'_>) -> Result<(), std::fmt::Error> { Ok(()) }
}

impl Transcript for MerlinTranscript {
  fn domain_separate(&mut self, label: &[u8]) {
    self.append_message(b"dom-sep", label);
  }

  fn append_message(&mut self, label: &'static [u8], message: &[u8]) {
    self.0.append_message(label, message);
  }

  fn challenge(&mut self, label: &'static [u8]) -> Vec<u8> {
    let mut challenge = vec![];
    // Uses a challenge length of 64 bytes to support wide reduction on generated scalars
    // From a security level standpoint, this should just be 32 bytes
    // From a Merlin standpoint, this should be variable per call
    // From a practical standpoint, this is a demo file not planned to be used and anything using
    // this wrapper is fine without any settings it uses
    challenge.resize(64, 0);
    self.0.challenge_bytes(label, &mut challenge);
    challenge
  }

  fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32] {
    let mut seed = [0; 32];
    transcript.challenge_bytes(label, &mut seed);
    seed
  }
}
