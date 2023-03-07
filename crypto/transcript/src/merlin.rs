use core::fmt::{Debug, Formatter};

use crate::Transcript;

/// A wrapper around a Merlin transcript which satisfiees the Transcript API.
///
/// Challenges are fixed to 64 bytes, despite Merlin supporting variable length challenges.
///
/// This implementation is intended to remain in the spirit of Merlin more than it's intended to be
/// in the spirit of the provided DigestTranscript. While DigestTranscript uses flags for each of
/// its different field types, the domain_separate function simply appends a message with a label
/// of "dom-sep", Merlin's preferred domain separation label. Since this could introduce transcript
/// conflicts between a domain separation and a message with a label of "dom-sep", the
/// append_message function uses an assertion to prevent such labels.
#[derive(Clone)]
pub struct MerlinTranscript(merlin::Transcript);
// Merlin doesn't implement Debug so provide a stub which won't panic
impl Debug for MerlinTranscript {
  fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt.debug_struct("MerlinTranscript").finish_non_exhaustive()
  }
}

impl Transcript for MerlinTranscript {
  // Uses a challenge length of 64 bytes to support wide reduction on commonly used EC scalars
  // From a security level standpoint (Merlin targets 128-bits), this should just be 32 bytes
  // From a Merlin standpoint, this should be variable per call
  // From a practical standpoint, this should be practical
  type Challenge = [u8; 64];

  fn new(name: &'static [u8]) -> Self {
    MerlinTranscript(merlin::Transcript::new(name))
  }

  fn domain_separate(&mut self, label: &'static [u8]) {
    self.0.append_message(b"dom-sep", label);
  }

  fn append_message<M: AsRef<[u8]>>(&mut self, label: &'static [u8], message: M) {
    assert!(
      label != "dom-sep".as_bytes(),
      "\"dom-sep\" is reserved for the domain_separate function",
    );
    self.0.append_message(label, message.as_ref());
  }

  fn challenge(&mut self, label: &'static [u8]) -> Self::Challenge {
    let mut challenge = [0; 64];
    self.0.challenge_bytes(label, &mut challenge);
    challenge
  }

  fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32] {
    let mut seed = [0; 32];
    seed.copy_from_slice(&self.challenge(label)[.. 32]);
    seed
  }
}
