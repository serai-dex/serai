use core::fmt;
use std_shims::string::String;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use rand_core::{RngCore, CryptoRng};

pub(crate) mod classic;
use classic::{CLASSIC_SEED_LENGTH, CLASSIC_SEED_LENGTH_WITH_CHECKSUM, ClassicSeed};

#[allow(clippy::std_instead_of_core)]
mod seed_error {
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
    #[cfg_attr(feature = "std", error("invalid seed"))]
    InvalidSeed,
  }
}
pub use seed_error::SeedError;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Language {
  Chinese,
  English,
  Dutch,
  French,
  Spanish,
  German,
  Italian,
  Portuguese,
  Japanese,
  Russian,
  Esperanto,
  Lojban,
  EnglishOld,
}

/// A Monero seed.
// TODO: Add polyseed to enum
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum Seed {
  Classic(ClassicSeed),
}

impl fmt::Debug for Seed {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Self::Classic(_) => f.debug_struct("Seed::Classic").finish_non_exhaustive(),
    }
  }
}

impl Seed {
  /// Create a new seed.
  #[must_use]
  pub fn new<R: RngCore + CryptoRng>(rng: &mut R, lang: Language) -> Self {
    Self::Classic(ClassicSeed::new(rng, lang))
  }

  /// Parse a seed from a String.
  pub fn from_string(words: Zeroizing<String>) -> Result<Self, SeedError> {
    match words.split_whitespace().count() {
      CLASSIC_SEED_LENGTH | CLASSIC_SEED_LENGTH_WITH_CHECKSUM => {
        ClassicSeed::from_string(words).map(Self::Classic)
      }
      _ => Err(SeedError::InvalidSeedLength)?,
    }
  }

  /// Create a Seed from entropy.
  #[must_use]
  pub fn from_entropy(lang: Language, entropy: Zeroizing<[u8; 32]>) -> Option<Self> {
    ClassicSeed::from_entropy(lang, entropy).map(Self::Classic)
  }

  /// Convert a seed to a String.
  pub fn to_string(&self) -> Zeroizing<String> {
    match self {
      Self::Classic(seed) => seed.to_string(),
    }
  }

  /// Return the entropy for this seed.
  #[must_use]
  pub fn entropy(&self) -> Zeroizing<[u8; 32]> {
    match self {
      Self::Classic(seed) => seed.entropy(),
    }
  }
}
