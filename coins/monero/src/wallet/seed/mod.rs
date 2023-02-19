use std::fmt;

use rand_core::OsRng;

use thiserror::Error;

mod classic;

use classic::{CLASSIC_SEED_LENGTH, CLASSIC_SEED_LENGTH_WITH_CHECKSUM};
use zeroize::Zeroizing;

/// Error when decoding a seed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum SeedError {
  #[error("malformed seed")]
  InvalidSeed,
  #[error("unknown language")]
  UnknownLanguage,
  #[error("unexpected number of words in seed")]
  InvalidSeedLength,
  #[error("language english old doesn't support seeds with checksum")]
  EnglishOldWithChecksum,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum LanguageName {
  English,
  EnglishOld,
  German,
  Spanish,
  French,
  Italian,
  Japanese,
  Dutch,
  Portuguese,
  Russian,
  Chinese,
  Esperanto,
  Lojban,
}

// TODO: Add polyseed to enum
#[derive(Clone, PartialEq, Eq)]
pub enum Seed {
  Classic(Zeroizing<String>),
}

impl Seed {
  /// creates a new seed.
  pub fn new(lang: LanguageName) -> Seed {
    // TODO: This should return Polyseed when implemented.
    Seed::Classic(classic::new(lang, &mut OsRng))
  }

  /// constructs a seed from seed words.
  pub fn from_string(words: Zeroizing<String>) -> Result<Seed, SeedError> {
    match words.split_whitespace().count() {
      CLASSIC_SEED_LENGTH | CLASSIC_SEED_LENGTH_WITH_CHECKSUM => {
        // convert to bytes to make sure it is valid
        classic::words_to_bytes(&words)?;
        Ok(Seed::Classic(words))
      }
      _ => Err(SeedError::InvalidSeedLength)?,
    }
  }

  /// constructs a seed from a given key.
  pub fn from_entropy(key: &Zeroizing<[u8; 32]>, lang_name: LanguageName) -> Seed {
    Seed::Classic(classic::bytes_to_words(key, lang_name))
  }

  /// returns seed as String.
  pub fn to_string(&self) -> &Zeroizing<String> {
    match self {
      Seed::Classic(words) => words,
    }
  }

  /// returns the seed spend key.
  pub fn entropy(&self) -> Zeroizing<[u8; 32]> {
    match self {
      Seed::Classic(words) => classic::words_to_bytes(words).unwrap(),
    }
  }
}

impl fmt::Debug for Seed {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    f.debug_struct("Seed::Classic").finish_non_exhaustive()
  }
}
