use core::fmt;
use std_shims::{sync::OnceLock, string::String, collections::HashMap};
#[cfg(feature = "std")]
use std::time::{SystemTime, UNIX_EPOCH};

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing, ZeroizeOnDrop};
use rand_core::{RngCore, CryptoRng};

use sha3::Sha3_256;
use pbkdf2::pbkdf2_hmac;

use super::SeedError;

// Features
const FEATURE_BITS: u8 = 5;
#[allow(dead_code)]
const INTERNAL_FEATURES: u8 = 2;
const USER_FEATURES: u8 = 3;

const USER_FEATURES_MASK: u8 = (1 << USER_FEATURES) - 1;
const ENCRYPTED_MASK: u8 = 1 << 4;
const RESERVED_FEATURES_MASK: u8 = ((1 << FEATURE_BITS) - 1) ^ ENCRYPTED_MASK;

fn user_features(features: u8) -> u8 {
  features & USER_FEATURES_MASK
}

fn polyseed_features_supported(features: u8) -> bool {
  (features & RESERVED_FEATURES_MASK) == 0
}

// Dates
const DATE_BITS: u8 = 10;
const DATE_MASK: u16 = (1u16 << DATE_BITS) - 1;
const POLYSEED_EPOCH: u64 = 1635768000; // 1st November 2021 12:00 UTC
pub(crate) const TIME_STEP: u64 = 2629746; // 30.436875 days = 1/12 of the Gregorian year

// After ~85 years, this will roll over.
fn birthday_encode(time: u64) -> u16 {
  u16::try_from((time.saturating_sub(POLYSEED_EPOCH) / TIME_STEP) & u64::from(DATE_MASK))
    .expect("value masked by 2**10 - 1 didn't fit into a u16")
}

fn birthday_decode(birthday: u16) -> u64 {
  POLYSEED_EPOCH + (u64::from(birthday) * TIME_STEP)
}

// Polyseed parameters
const SECRET_BITS: usize = 150;

const BITS_PER_BYTE: usize = 8;
// ceildiv of SECRET_BITS by BITS_PER_BYTE
const SECRET_SIZE: usize = (SECRET_BITS + BITS_PER_BYTE - 1) / BITS_PER_BYTE; // 19
const CLEAR_BITS: usize = (SECRET_SIZE * BITS_PER_BYTE) - SECRET_BITS; // 2

// Polyseed calls this CLEAR_MASK and has a very complicated formula for this fundamental
// equivalency
const LAST_BYTE_SECRET_BITS_MASK: u8 = ((1 << (BITS_PER_BYTE - CLEAR_BITS)) - 1) as u8;

const SECRET_BITS_PER_WORD: usize = 10;

// Amount of words in a seed
pub(crate) const POLYSEED_LENGTH: usize = 16;
// Amount of characters each word must have if trimmed
pub(crate) const PREFIX_LEN: usize = 4;

const POLY_NUM_CHECK_DIGITS: usize = 1;
const DATA_WORDS: usize = POLYSEED_LENGTH - POLY_NUM_CHECK_DIGITS;

// Polynomial
const GF_BITS: usize = 11;
const POLYSEED_MUL2_TABLE: [u16; 8] = [5, 7, 1, 3, 13, 15, 9, 11];

type Poly = [u16; POLYSEED_LENGTH];

fn elem_mul2(x: u16) -> u16 {
  if x < 1024 {
    return 2 * x;
  }
  POLYSEED_MUL2_TABLE[usize::from(x % 8)] + (16 * ((x - 1024) / 8))
}

fn poly_eval(poly: &Poly) -> u16 {
  // Horner's method at x = 2
  let mut result = poly[POLYSEED_LENGTH - 1];
  for i in (0 .. (POLYSEED_LENGTH - 1)).rev() {
    result = elem_mul2(result) ^ poly[i];
  }
  result
}

// Key gen parameters
const POLYSEED_SALT: &[u8] = b"POLYSEED key";
const POLYSEED_KEYGEN_ITERATIONS: u32 = 10000;

// Polyseed technically supports multiple coins, and the value for Monero is 0
// See: https://github.com/tevador/polyseed/blob/master/include/polyseed.h#L58
const COIN: u16 = 0;

/// Language options for Polyseed.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize)]
pub enum Language {
  English,
  Spanish,
  French,
  Italian,
  Japanese,
  Korean,
  Czech,
  Portuguese,
  ChineseSimplified,
  ChineseTraditional,
}

struct WordList {
  words: Vec<String>,
  has_prefix: bool,
  has_accent: bool,
}

impl WordList {
  fn new(words: &str, has_prefix: bool, has_accent: bool) -> WordList {
    let res = WordList { words: serde_json::from_str(words).unwrap(), has_prefix, has_accent };
    // This is needed for a later unwrap to not fails
    assert!(words.len() < usize::from(u16::MAX));
    res
  }
}

static LANGUAGES_CELL: OnceLock<HashMap<Language, WordList>> = OnceLock::new();
#[allow(non_snake_case)]
fn LANGUAGES() -> &'static HashMap<Language, WordList> {
  LANGUAGES_CELL.get_or_init(|| {
    HashMap::from([
      (Language::Czech, WordList::new(include_str!("./polyseed/cs.json"), true, false)),
      (Language::French, WordList::new(include_str!("./polyseed/fr.json"), true, true)),
      (Language::Korean, WordList::new(include_str!("./polyseed/ko.json"), false, false)),
      (Language::English, WordList::new(include_str!("./polyseed/en.json"), true, false)),
      (Language::Italian, WordList::new(include_str!("./polyseed/it.json"), true, false)),
      (Language::Spanish, WordList::new(include_str!("./polyseed/es.json"), true, true)),
      (Language::Japanese, WordList::new(include_str!("./polyseed/ja.json"), false, false)),
      (Language::Portuguese, WordList::new(include_str!("./polyseed/pt.json"), true, false)),
      (
        Language::ChineseSimplified,
        WordList::new(include_str!("./polyseed/zh_simplified.json"), false, false),
      ),
      (
        Language::ChineseTraditional,
        WordList::new(include_str!("./polyseed/zh_traditional.json"), false, false),
      ),
    ])
  })
}

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Polyseed {
  language: Language,
  features: u8,
  birthday: u16,
  entropy: Zeroizing<[u8; 32]>,
  checksum: u16,
}

impl fmt::Debug for Polyseed {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    f.debug_struct("Polyseed").finish_non_exhaustive()
  }
}

fn valid_entropy(entropy: &Zeroizing<[u8; 32]>) -> bool {
  // Last byte of the entropy should only use certain bits
  let mut res =
    entropy[SECRET_SIZE - 1].ct_eq(&(entropy[SECRET_SIZE - 1] & LAST_BYTE_SECRET_BITS_MASK));
  // Last 13 bytes of the buffer should be unused
  for b in SECRET_SIZE .. entropy.len() {
    res &= entropy[b].ct_eq(&0);
  }
  res.into()
}

impl Polyseed {
  // TODO: Clean this
  fn to_poly(&self) -> Poly {
    let mut extra_bits = u32::from(FEATURE_BITS + DATE_BITS);
    let extra_val = (u16::from(self.features) << DATE_BITS) | self.birthday;

    let mut entropy_idx = 0;
    let mut secret_bits = BITS_PER_BYTE;
    let mut seed_rem_bits = SECRET_BITS - BITS_PER_BYTE;

    let mut poly = [0; POLYSEED_LENGTH];
    for i in 0 .. DATA_WORDS {
      extra_bits -= 1;

      let mut word_bits = 0;
      let mut word_val = 0;
      while word_bits < SECRET_BITS_PER_WORD {
        if secret_bits == 0 {
          entropy_idx += 1;
          secret_bits = seed_rem_bits.min(BITS_PER_BYTE);
          seed_rem_bits -= secret_bits;
        }
        let chunk_bits = secret_bits.min(SECRET_BITS_PER_WORD - word_bits);
        secret_bits -= chunk_bits;
        word_bits += chunk_bits;
        word_val <<= chunk_bits;
        word_val |=
          (u16::from(self.entropy[entropy_idx]) >> secret_bits) & ((1u16 << chunk_bits) - 1);
      }

      word_val <<= 1;
      word_val |= (extra_val >> extra_bits) & 1;
      poly[POLY_NUM_CHECK_DIGITS + i] = word_val;
    }

    poly
  }

  /// Create a new `Polyseed` with specific internals.
  ///
  /// `birthday` is defined in seconds since the Unix epoch.
  pub fn from(
    language: Language,
    features: u8,
    birthday: u64,
    entropy: Zeroizing<[u8; 32]>,
  ) -> Result<Polyseed, SeedError> {
    let features = user_features(features);
    if !polyseed_features_supported(features) {
      Err(SeedError::UnsupportedFeatures)?;
    }

    let birthday = birthday_encode(birthday);

    if !valid_entropy(&entropy) {
      Err(SeedError::InvalidEntropy)?;
    }

    let mut res = Polyseed { language, birthday, features, entropy, checksum: 0 };
    res.checksum = poly_eval(&res.to_poly());
    Ok(res)
  }

  /// Create a new `Polyseed`.
  ///
  /// This uses the system's time for the birthday, if available.
  pub fn new<R: RngCore + CryptoRng>(rng: &mut R, language: Language) -> Polyseed {
    // Get the birthday
    #[cfg(feature = "std")]
    let birthday = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    #[cfg(not(feature = "std"))]
    let birthday = 0;

    // Derive entropy
    let mut entropy = Zeroizing::new([0; 32]);
    rng.fill_bytes(entropy.as_mut());
    entropy[SECRET_SIZE ..].fill(0);
    entropy[SECRET_SIZE - 1] &= LAST_BYTE_SECRET_BITS_MASK;

    Self::from(language, 0, birthday, entropy).unwrap()
  }

  /// Create a new `Polyseed` from a String.
  pub fn from_string(seed: Zeroizing<String>) -> Result<Polyseed, SeedError> {
    // Decode the seed into its polynomial coefficients
    let mut poly = [0; POLYSEED_LENGTH];
    let lang = (|| {
      'language: for (name, lang) in LANGUAGES().iter() {
        for (i, word) in seed.split_whitespace().enumerate() {
          // Find the word's index
          fn check_if_matches<S: AsRef<str>, I: Iterator<Item = S>>(
            has_prefix: bool,
            mut lang_words: I,
            word: &str,
          ) -> Option<usize> {
            if has_prefix {
              // Get the position of the word within the iterator
              // Doesn't use starts_with and some words are substrs of others, leading to false
              // positives
              let mut get_position = || {
                lang_words.position(|lang_word| {
                  let mut lang_word = lang_word.as_ref().chars();
                  let mut word = word.chars();

                  let mut res = true;
                  for _ in 0 .. PREFIX_LEN {
                    res &= lang_word.next() == word.next();
                  }
                  res
                })
              };
              let res = get_position();
              // If another word has this prefix, don't call it a match
              if get_position().is_some() {
                return None;
              }
              res
            } else {
              lang_words.position(|lang_word| lang_word.as_ref() == word)
            }
          }

          let Some(coeff) = (if lang.has_accent {
            let ascii = |word: &str| word.chars().filter(|c| c.is_ascii()).collect::<String>();
            check_if_matches(
              lang.has_prefix,
              lang.words.iter().map(|lang_word| ascii(lang_word)),
              &ascii(word)
            )
          } else {
            check_if_matches(lang.has_prefix, lang.words.iter(), word)
          }) else { continue 'language; };

          // WordList asserts the word list length is less than u16::MAX
          poly[i] = u16::try_from(coeff).expect("coeff exceeded u16");
        }

        return Ok(*name);
      }

      Err(SeedError::UnknownLanguage)
    })()?;

    // xor out the coin
    poly[POLY_NUM_CHECK_DIGITS] ^= COIN;

    // Validate the checksum
    if poly_eval(&poly) != 0 {
      Err(SeedError::InvalidChecksum)?;
    }

    // Convert the polynomial into entropy
    let mut entropy = Zeroizing::new([0; 32]);

    let mut extra = 0;

    let mut entropy_idx = 0;
    let mut entropy_bits = 0;

    let checksum = poly[0];
    for mut word_val in poly.into_iter().skip(POLY_NUM_CHECK_DIGITS) {
      // Parse the bottom bit, which is one of the bits of extra
      // This iterates for less than 16 iters, meaning this won't drop any bits
      extra <<= 1;
      extra |= word_val & 1;
      word_val >>= 1;

      // 10 bits per word creates a [8, 2], [6, 4], [4, 6], [2, 8] cycle
      // 15 % 4 is 3, leaving 2 bits off, and 152 (19 * 8) - 2 is 150, the amount of bits in the
      // secret
      let mut word_bits = GF_BITS - 1;
      while word_bits > 0 {
        if entropy_bits == BITS_PER_BYTE {
          entropy_idx += 1;
          entropy_bits = 0;
        }
        let chunk_bits = word_bits.min(BITS_PER_BYTE - entropy_bits);
        word_bits -= chunk_bits;
        let chunk_mask = (1u16 << chunk_bits) - 1;
        if chunk_bits < BITS_PER_BYTE {
          entropy[entropy_idx] <<= chunk_bits;
        }
        entropy[entropy_idx] |=
          u8::try_from((word_val >> word_bits) & chunk_mask).expect("chunk exceeded u8");
        entropy_bits += chunk_bits;
      }
    }

    let birthday = extra & DATE_MASK;
    // extra is contained to u16, and DATE_BITS > 8
    let features =
      u8::try_from(extra >> DATE_BITS).expect("couldn't convert extra >> DATE_BITS to u8");

    let res = Polyseed::from(lang, features, birthday_decode(birthday), entropy);
    if let Ok(res) = res.as_ref() {
      debug_assert_eq!(res.checksum, checksum);
    }
    res
  }

  /// When this seed was created, defined in seconds since the epoch.
  pub fn birthday(&self) -> u64 {
    birthday_decode(self.birthday)
  }

  /// This seed's features.
  pub fn features(&self) -> u8 {
    self.features
  }

  /// This seed's entropy.
  pub fn entropy(&self) -> &Zeroizing<[u8; 32]> {
    &self.entropy
  }

  /// The key derived from this seed.
  pub fn key(&self) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0; 32]);
    pbkdf2_hmac::<Sha3_256>(
      self.entropy.as_slice(),
      POLYSEED_SALT,
      POLYSEED_KEYGEN_ITERATIONS,
      key.as_mut(),
    );
    key
  }

  pub fn to_string(&self) -> Zeroizing<String> {
    // Encode the polynomial with the existing checksum
    let mut poly = self.to_poly();
    poly[0] = self.checksum;

    // Embed the coin
    poly[POLY_NUM_CHECK_DIGITS] ^= COIN;

    // Output words
    let mut seed = Zeroizing::new(String::new());
    let words = &LANGUAGES()[&self.language].words;
    for i in 0 .. poly.len() {
      seed.push_str(&words[usize::from(poly[i])]);
      if i < poly.len() - 1 {
        seed.push(' ');
      }
    }

    seed
  }
}
