use core::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use rand_core::{RngCore, CryptoRng};

use thiserror::Error;

pub(crate) mod classic;
pub(crate) mod polyseed;
use classic::{CLASSIC_SEED_LENGTH, CLASSIC_SEED_LENGTH_WITH_CHECKSUM, ClassicSeed};
use polyseed::{POLYSEED_LENGTH, PolySeed, PolySeedData};

/// Error when decoding a seed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum SeedError {
  #[error("invalid number of words in seed")]
  InvalidSeedLength,
  #[error("unknown language")]
  UnknownLanguage,
  #[error("invalid checksum")]
  InvalidChecksum,
  #[error("english old seeds don't support checksums")]
  EnglishOldWithChecksum,
  #[error("invalid seed")]
  InvalidSeed,
  #[error("invalid poly to decode")]
  PolySeedInvalidPoly,
  #[error("provided features are not supported")]
  PolySeedFeatureNotSupported,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SeedType {
  Classic(classic::Language),
  PolySeed(polyseed::Language),
}

/// A Monero seed.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum Seed {
  Classic(ClassicSeed),
  PolySeed(PolySeed),
}

impl fmt::Debug for Seed {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Seed::Classic(_) => f.debug_struct("Seed::Classic").finish_non_exhaustive(),
      Seed::PolySeed(_) => f.debug_struct("Seed::Polyseed").finish_non_exhaustive(),
    }
  }
}

impl Seed {
  /// Create a new seed.
  pub fn new<R: RngCore + CryptoRng>(rng: &mut R, seed_type: SeedType) -> Seed {
    match seed_type {
      SeedType::Classic(lang) => Seed::Classic(ClassicSeed::new(rng, lang)),
      SeedType::PolySeed(lang) => Seed::PolySeed(PolySeed::new(rng, lang)),
    }
  }

  /// Parse a seed from a String.
  pub fn from_string(words: Zeroizing<String>) -> Result<Seed, SeedError> {
    match words.split_whitespace().count() {
      CLASSIC_SEED_LENGTH | CLASSIC_SEED_LENGTH_WITH_CHECKSUM => {
        ClassicSeed::from_string(words).map(Seed::Classic)
      }
      POLYSEED_LENGTH => PolySeed::from_string(words).map(Seed::PolySeed),
      _ => Err(SeedError::InvalidSeedLength)?,
    }
  }

  /// Create a Seed from entropy.
  pub fn from_entropy(seed_type: SeedType, entropy: Zeroizing<[u8; 32]>) -> Option<Seed> {
    match seed_type {
      SeedType::Classic(lang) => ClassicSeed::from_entropy(lang, entropy).map(Seed::Classic),
      SeedType::PolySeed(lang) => {
        let birthday = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let data = PolySeedData { birthday, features: 0, entropy, checksum: 0 };
        PolySeed::from_polyseed_data(data, lang).map(Seed::PolySeed)
      }
    }
  }

  /// Create a Seed from given data.
  pub fn from_polyseed_data(data: PolySeedData, lang: polyseed::Language) -> Option<Seed> {
    PolySeed::from_polyseed_data(data, lang).map(Seed::PolySeed)
  }

  /// Convert a seed to a String.
  pub fn to_string(&self) -> Zeroizing<String> {
    match self {
      Seed::Classic(seed) => seed.to_string(),
      Seed::PolySeed(seed) => seed.to_string(),
    }
  }

  /// Return the entropy for this seed.
  pub fn entropy(&self) -> Zeroizing<[u8; 32]> {
    match self {
      Seed::Classic(seed) => seed.entropy(),
      Seed::PolySeed(seed) => seed.polyseed_data().entropy,
    }
  }

  /// Return the polyseed data for this seed.
  /// Return 0 values if it is a classic seed.
  pub fn polyseed_data(&self) -> PolySeedData {
    match self {
      Seed::PolySeed(seed) => seed.polyseed_data(),
      Seed::Classic(_) => {
        PolySeedData { birthday: 0, features: 0, entropy: Zeroizing::new([0; 32]), checksum: 0 }
      }
    }
  }
}
