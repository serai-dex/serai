use core::fmt;
use std_shims::string::String;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use rand_core::{RngCore, CryptoRng};

pub(crate) mod classic;
pub(crate) mod polyseed;
use classic::{CLASSIC_SEED_LENGTH, CLASSIC_SEED_LENGTH_WITH_CHECKSUM, ClassicSeed};
use polyseed::{POLYSEED_LENGTH, Polyseed};

/// Error when decoding a seed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum SeedError {
  #[cfg_attr(feature = "std", error("invalid number of words in seed"))]
  InvalidSeedLength,
  #[cfg_attr(feature = "std", error("unknown language"))]
  UnknownLanguage,
  #[cfg_attr(feature = "std", error("invalid checksum"))]
  InvalidChecksum,
  #[cfg_attr(feature = "std", error("english old seeds don't support checksums"))]
  EnglishOldWithChecksum,
  #[cfg_attr(feature = "std", error("provided entropy is not valid"))]
  InvalidEntropy,
  #[cfg_attr(feature = "std", error("invalid seed"))]
  InvalidSeed,
  #[cfg_attr(feature = "std", error("provided features are not supported"))]
  UnsupportedFeatures,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SeedType {
  Classic(classic::Language),
  Polyseed(polyseed::Language),
}

/// A Monero seed.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum Seed {
  Classic(ClassicSeed),
  Polyseed(Polyseed),
}

impl fmt::Debug for Seed {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Seed::Classic(_) => f.debug_struct("Seed::Classic").finish_non_exhaustive(),
      Seed::Polyseed(_) => f.debug_struct("Seed::Polyseed").finish_non_exhaustive(),
    }
  }
}

impl Seed {
  /// Creates a new `Seed`.
  pub fn new<R: RngCore + CryptoRng>(rng: &mut R, seed_type: SeedType) -> Seed {
    match seed_type {
      SeedType::Classic(lang) => Seed::Classic(ClassicSeed::new(rng, lang)),
      SeedType::Polyseed(lang) => Seed::Polyseed(Polyseed::new(rng, lang)),
    }
  }

  /// Parse a seed from a `String`.
  pub fn from_string(words: Zeroizing<String>) -> Result<Seed, SeedError> {
    match words.split_whitespace().count() {
      CLASSIC_SEED_LENGTH | CLASSIC_SEED_LENGTH_WITH_CHECKSUM => {
        ClassicSeed::from_string(words).map(Seed::Classic)
      }
      POLYSEED_LENGTH => Polyseed::from_string(words).map(Seed::Polyseed),
      _ => Err(SeedError::InvalidSeedLength)?,
    }
  }

  /// Creates a `Seed` from an entropy and an optional birthday (denoted in seconds since the
  /// epoch).
  ///
  /// For `SeedType::Classic`, the birthday is ignored.
  ///
  /// For `SeedType::Polyseed`, the last 13 bytes of `entropy` must be `0`.
  // TODO: Return Result, not Option
  pub fn from_entropy(
    seed_type: SeedType,
    entropy: Zeroizing<[u8; 32]>,
    birthday: Option<u64>,
  ) -> Option<Seed> {
    match seed_type {
      SeedType::Classic(lang) => ClassicSeed::from_entropy(lang, entropy).map(Seed::Classic),
      SeedType::Polyseed(lang) => {
        Polyseed::from(lang, 0, birthday.unwrap_or(0), entropy).map(Seed::Polyseed).ok()
      }
    }
  }

  /// Returns seed as `String`.
  pub fn to_string(&self) -> Zeroizing<String> {
    match self {
      Seed::Classic(seed) => seed.to_string(),
      Seed::Polyseed(seed) => seed.to_string(),
    }
  }

  /// Returns the entropy for this `Seed`.
  pub fn entropy(&self) -> Zeroizing<[u8; 32]> {
    match self {
      Seed::Classic(seed) => seed.entropy(),
      Seed::Polyseed(seed) => seed.entropy().clone(),
    }
  }

  /// Returns the key derived from this `Seed`.
  pub fn key(&self) -> Zeroizing<[u8; 32]> {
    match self {
      // Classic does not differentiate between its entropy and its key
      Seed::Classic(seed) => seed.entropy(),
      Seed::Polyseed(seed) => seed.key(),
    }
  }

  /// Returns the birthday of this `Seed`.
  pub fn birthday(&self) -> u64 {
    match self {
      Seed::Classic(_) => 0,
      Seed::Polyseed(seed) => seed.birthday(),
    }
  }
}
