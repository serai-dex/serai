use core::fmt::{Debug, Formatter};

use crate::Transcript;

#[derive(Clone)]
pub struct MerlinTranscript(pub merlin::Transcript);
// Merlin doesn't implement Debug so provide a stub which won't panic
impl Debug for MerlinTranscript {
  fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt.debug_struct("MerlinTranscript").finish()
  }
}

impl Transcript for MerlinTranscript {
  // Uses a challenge length of 64 bytes to support wide reduction on generated scalars
  // From a security level standpoint, this should just be 32 bytes
  // From a Merlin standpoint, this should be variable per call
  // From a practical standpoint, this is a demo file not planned to be used and anything using
  // this wrapper should be secure with this setting
  type Challenge = [u8; 64];

  fn new(name: &'static [u8]) -> Self {
    MerlinTranscript(merlin::Transcript::new(name))
  }

  fn domain_separate(&mut self, label: &'static [u8]) {
    self.append_message(b"dom-sep", label);
  }

  fn append_message<M: AsRef<[u8]>>(&mut self, label: &'static [u8], message: M) {
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
