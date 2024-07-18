use core::fmt;
use std_shims::string::String;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use rand_core::{RngCore, CryptoRng};

pub use monero_seed as original;
pub use polyseed;

use original::{SeedError as OriginalSeedError, Seed as OriginalSeed};
use polyseed::{PolyseedError, Polyseed};

/// An error from working with seeds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum SeedError {
  /// The seed was invalid.
  #[cfg_attr(feature = "std", error("invalid seed"))]
  InvalidSeed,
  /// The entropy was invalid.
  #[cfg_attr(feature = "std", error("invalid entropy"))]
  InvalidEntropy,
  /// The checksum did not match the data.
  #[cfg_attr(feature = "std", error("invalid checksum"))]
  InvalidChecksum,
  /// Unsupported features were enabled.
  #[cfg_attr(feature = "std", error("unsupported features"))]
  UnsupportedFeatures,
}

impl From<OriginalSeedError> for SeedError {
  fn from(error: OriginalSeedError) -> SeedError {
    match error {
      OriginalSeedError::DeprecatedEnglishWithChecksum | OriginalSeedError::InvalidChecksum => {
        SeedError::InvalidChecksum
      }
      OriginalSeedError::InvalidSeed => SeedError::InvalidSeed,
    }
  }
}

impl From<PolyseedError> for SeedError {
  fn from(error: PolyseedError) -> SeedError {
    match error {
      PolyseedError::UnsupportedFeatures => SeedError::UnsupportedFeatures,
      PolyseedError::InvalidEntropy => SeedError::InvalidEntropy,
      PolyseedError::InvalidSeed => SeedError::InvalidSeed,
      PolyseedError::InvalidChecksum => SeedError::InvalidChecksum,
    }
  }
}

/// The type of the seed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SeedType {
  /// The seed format originally used by Monero,
  Original(monero_seed::Language),
  /// Polyseed.
  Polyseed(polyseed::Language),
}

/// A seed, internally either the original format or a Polyseed.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum Seed {
  /// The originally formatted seed.
  Original(OriginalSeed),
  /// A Polyseed.
  Polyseed(Polyseed),
}

impl fmt::Debug for Seed {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Seed::Original(_) => f.debug_struct("Seed::Original").finish_non_exhaustive(),
      Seed::Polyseed(_) => f.debug_struct("Seed::Polyseed").finish_non_exhaustive(),
    }
  }
}

impl Seed {
  /// Create a new seed.
  pub fn new<R: RngCore + CryptoRng>(rng: &mut R, seed_type: SeedType) -> Seed {
    match seed_type {
      SeedType::Original(lang) => Seed::Original(OriginalSeed::new(rng, lang)),
      SeedType::Polyseed(lang) => Seed::Polyseed(Polyseed::new(rng, lang)),
    }
  }

  /// Parse a seed from a string.
  pub fn from_string(seed_type: SeedType, words: Zeroizing<String>) -> Result<Seed, SeedError> {
    match seed_type {
      SeedType::Original(lang) => Ok(OriginalSeed::from_string(lang, words).map(Seed::Original)?),
      SeedType::Polyseed(lang) => Ok(Polyseed::from_string(lang, words).map(Seed::Polyseed)?),
    }
  }

  /// Create a seed from entropy.
  ///
  /// A birthday may be optionally provided, denoted in seconds since the epoch. For
  /// SeedType::Original, it will be ignored. For SeedType::Polyseed, it'll be embedded into the
  /// seed.
  ///
  /// For SeedType::Polyseed, the last 13 bytes of `entropy` must be 0.
  // TODO: Return Result, not Option
  pub fn from_entropy(
    seed_type: SeedType,
    entropy: Zeroizing<[u8; 32]>,
    birthday: Option<u64>,
  ) -> Option<Seed> {
    match seed_type {
      SeedType::Original(lang) => OriginalSeed::from_entropy(lang, entropy).map(Seed::Original),
      SeedType::Polyseed(lang) => {
        Polyseed::from(lang, 0, birthday.unwrap_or(0), entropy).ok().map(Seed::Polyseed)
      }
    }
  }

  /// Converts the seed to a string.
  pub fn to_string(&self) -> Zeroizing<String> {
    match self {
      Seed::Original(seed) => seed.to_string(),
      Seed::Polyseed(seed) => seed.to_string(),
    }
  }

  /// Get the entropy for this seed.
  pub fn entropy(&self) -> Zeroizing<[u8; 32]> {
    match self {
      Seed::Original(seed) => seed.entropy(),
      Seed::Polyseed(seed) => seed.entropy().clone(),
    }
  }

  /// Get the key derived from this seed.
  pub fn key(&self) -> Zeroizing<[u8; 32]> {
    match self {
      // Original does not differentiate between its entropy and its key
      Seed::Original(seed) => seed.entropy(),
      Seed::Polyseed(seed) => seed.key(),
    }
  }

  /// Get the birthday of this seed, denoted in seconds since the epoch.
  pub fn birthday(&self) -> u64 {
    match self {
      Seed::Original(_) => 0,
      Seed::Polyseed(seed) => seed.birthday(),
    }
  }
}
