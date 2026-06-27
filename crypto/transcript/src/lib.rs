#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

use zeroize::ZeroizeOnDrop;

use digest::{Digest, Output};

#[cfg(feature = "merlin")]
mod merlin;
#[cfg(feature = "merlin")]
pub use crate::merlin::MerlinTranscript;

/// Tests for a transcript.
#[cfg(any(test, feature = "tests"))]
pub mod tests;

/// A transcript trait valid over a variety of transcript formats.
pub trait Transcript: Send + Clone {
  /// A challenge sampled from the transcript.
  type Challenge: Send + Sync + Clone + AsRef<[u8]>;

  /// Create a new transcript with the specified name.
  fn new(name: &'static [u8]) -> Self;

  /// Apply a domain separator to the transcript.
  fn domain_separate(&mut self, label: &'static [u8]);

  /// Append a message to the transcript.
  fn append_message<M: AsRef<[u8]>>(&mut self, label: &'static [u8], message: M);

  /// Produce a challenge.
  ///
  /// Implementors MUST update the transcript as it does so, preventing the same challenge from
  /// being generated multiple times.
  fn challenge(&mut self, label: &'static [u8]) -> Self::Challenge;

  /// Produce a RNG seed.
  ///
  /// Helper function for parties needing to generate random data from an agreed upon state.
  ///
  /// Implementors MAY internally call the challenge function for the needed bytes, and accordingly
  /// produce a transcript conflict between two transcripts, one which called challenge(label) and
  /// one which called rng_seed(label) at the same point.
  fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32];
}

#[derive(Clone, Copy)]
enum DigestTranscriptMember {
  Name,
  Domain,
  Label,
  Value,
  Challenge,
  Continued,
  Challenged,
}

impl DigestTranscriptMember {
  fn as_u8(self) -> u8 {
    match self {
      DigestTranscriptMember::Name => 0,
      DigestTranscriptMember::Domain => 1,
      DigestTranscriptMember::Label => 2,
      DigestTranscriptMember::Value => 3,
      DigestTranscriptMember::Challenge => 4,
      DigestTranscriptMember::Continued => 5,
      DigestTranscriptMember::Challenged => 6,
    }
  }
}

/// A simple transcript format constructed around the specified hash algorithm.
#[derive(Clone, Debug)]
pub struct DigestTranscript<D: Send + Clone + Digest>(D);

impl<D: Send + Clone + Digest> DigestTranscript<D> {
  fn append(&mut self, kind: DigestTranscriptMember, value: &[u8]) {
    self.0.update([kind.as_u8()]);
    // Assumes messages don't exceed 16 exabytes
    self.0.update(u64::try_from(value.len()).unwrap().to_le_bytes());
    self.0.update(value);
  }
}

impl<D: Send + Clone + Digest> Transcript for DigestTranscript<D> {
  type Challenge = Output<D>;

  fn new(name: &'static [u8]) -> Self {
    let mut res = DigestTranscript(D::new());
    res.append(DigestTranscriptMember::Name, name);
    res
  }

  fn domain_separate(&mut self, label: &'static [u8]) {
    self.append(DigestTranscriptMember::Domain, label);
  }

  fn append_message<M: AsRef<[u8]>>(&mut self, label: &'static [u8], message: M) {
    self.append(DigestTranscriptMember::Label, label);
    self.append(DigestTranscriptMember::Value, message.as_ref());
  }

  fn challenge(&mut self, label: &'static [u8]) -> Self::Challenge {
    self.append(DigestTranscriptMember::Challenge, label);
    let mut cloned = self.0.clone();

    // Explicitly fork these transcripts to prevent length extension attacks from being possible
    // (at least, without the additional ability to remove a byte from a finalized hash)
    self.0.update([DigestTranscriptMember::Continued.as_u8()]);
    cloned.update([DigestTranscriptMember::Challenged.as_u8()]);
    cloned.finalize()
  }

  fn rng_seed(&mut self, label: &'static [u8]) -> [u8; 32] {
    let mut seed = [0; 32];
    seed.copy_from_slice(&self.challenge(label)[.. 32]);
    seed
  }
}

impl<D: Send + Clone + Digest + ZeroizeOnDrop + ZeroizeOnDrop> ZeroizeOnDrop
  for DigestTranscript<D>
{
}

#[cfg(feature = "recommended")]
mod recommended {
  use core::fmt;

  use blake2::{
    digest::{
      self, array::sizes::U64, block_api::FixedOutputCore, Update, OutputSizeUser, Output,
      FixedOutput, HashMarker,
    },
    Blake2bVarCore,
  };

  use super::*;

  /// Immediately `zeroize` a `struct` which implements `ZeroizeOnDrop` but not `Zeroize`.
  ///
  /// This effects behavior equivalent to `Zeroize` when `DefaultIsZeroes`. It's primarily intended
  /// just to assert the value does in fact implement `ZeroizeOnDrop` and explicitly track this.
  fn zeroize_zeroize_on_drop<T: Default + ZeroizeOnDrop>(value: &mut T) {
    let mut replacement = T::default();
    core::mem::swap(value, &mut replacement);
    drop(replacement);
  }

  // We need to locally define this struct in order to be able to access its fields
  digest::buffer_ct_variable!(
    struct Blake2b<Out>(Blake2bVarCore);
    exclude: SerializableState;
    max_size: U64;
  );
  type Blake2b512 = Blake2b<U64>;

  /// A `Blake2b512` which implements `ZeroizeOnDrop` because `blake2::Blake2b` does not.
  #[derive(Clone, Default)]
  pub struct ZeroizeOnDropBlake2b512(Blake2b512);
  impl fmt::Debug for ZeroizeOnDropBlake2b512 {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
      fmt.debug_struct("ZeroizeOnDropBlake2b512").finish_non_exhaustive()
    }
  }
  impl Update for ZeroizeOnDropBlake2b512 {
    fn update(&mut self, data: &[u8]) {
      Update::update(&mut self.0, data);
    }
  }
  impl OutputSizeUser for ZeroizeOnDropBlake2b512 {
    type OutputSize = U64;
  }
  impl FixedOutput for ZeroizeOnDropBlake2b512 {
    fn finalize_into(mut self, out: &mut Output<Self>) {
      FixedOutputCore::finalize_fixed_core(&mut self.0.core, &mut self.0.buffer, out);
      drop(self);
    }
  }
  impl HashMarker for ZeroizeOnDropBlake2b512 {}
  impl Drop for ZeroizeOnDropBlake2b512 {
    fn drop(&mut self) {
      let Self(Blake2b { core, buffer }) = self;
      zeroize_zeroize_on_drop(core);
      zeroize_zeroize_on_drop(buffer);
    }
  }
  impl ZeroizeOnDrop for ZeroizeOnDropBlake2b512 {}

  /// The recommended transcript, guaranteed to be secure against length-extension attacks.
  pub type RecommendedTranscript = DigestTranscript<ZeroizeOnDropBlake2b512>;

  // TODO: Remove the following after `monero-oxide` updates
  impl zeroize::Zeroize for RecommendedTranscript {
    fn zeroize(&mut self) {
      zeroize_zeroize_on_drop(&mut self.0);
    }
  }

  #[test]
  fn bespoke_blake2b512_is_blake2b512() {
    use blake2::Digest as _;
    assert_eq!(blake2::Blake2b512::digest(b""), ZeroizeOnDropBlake2b512::digest(b""));
  }
}
#[cfg(feature = "recommended")]
pub use recommended::RecommendedTranscript;
