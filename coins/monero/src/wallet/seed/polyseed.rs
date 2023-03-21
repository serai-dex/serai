use std::{
  cmp::min,
  collections::HashMap,
  time::{SystemTime, UNIX_EPOCH},
};

use pbkdf2::pbkdf2_hmac;
use sha3::Sha3_256;

use rand_core::{RngCore, CryptoRng};
use zeroize::{Zeroize, Zeroizing};

use lazy_static::lazy_static;

use super::SeedError;

// features
const FEATURE_BITS: u32 = 5;
const USER_FEATURES: u32 = 3;
const USER_FEATURES_MASK: u32 = (1 << USER_FEATURES) - 1;
const RESERVED_FEATURES: u32 = ((1 << FEATURE_BITS) - 1) ^ 16;

// dates
const DATE_BITS: u32 = 10;
const DATE_MASK: u32 = (1 << DATE_BITS) - 1;
const EPOCH: u64 = 1635768000; // 1st November 2021 12:00 UTC
const TIME_STEP: u64 = 2629746; // 30.436875 days = 1/12 of the Gregorian year

// poly
const SECRET_BITS: u32 = 150;
const CHAR_BIT: u32 = 8;
const SECRET_SIZE: usize = ((SECRET_BITS + CHAR_BIT - 1) / CHAR_BIT) as usize; /* 19 */
const SHARE_BITS: u32 = 10; // bits of the secret per word
const CLEAR_MASK: u8 = !((((1 << (2)) - 1) << (8 - (2))) as u8);
const GF_BITS: u32 = 11;
const POLY_NUM_CHECK_DIGITS: usize = 1;
const POLYSEED_MUL2_TABLE: [u16; 8] = [5, 7, 1, 3, 13, 15, 9, 11];

// keygen
const POLYSEED_SALT: &str = "POLYSEED key";
const POLYSEED_KEYGEN_ITERATIONS: u32 = 10000;

// words
pub const POLYSEED_LENGTH: usize = 16;
const DATA_WORDS: usize = POLYSEED_LENGTH - POLY_NUM_CHECK_DIGITS;

// there is more than 1 coin in the original polyseed implementation
// and the value for monero is always 0.
// see: https://github.com/tevador/polyseed/blob/master/include/polyseed.h#L58
const COIN: u16 = 0;

// Polynomial type
type Poly = [u16; POLYSEED_LENGTH];

// language names
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
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
  pub fn new(words: &str, has_prefix: bool, has_accent: bool) -> WordList {
    WordList { words: serde_json::from_str(words).unwrap(), has_prefix, has_accent }
  }
}

// language words
const CS_WORDS: &str = include_str!("./polyseed/cs.json");
const FR_WORDS: &str = include_str!("./polyseed/fr.json");
const KO_WORDS: &str = include_str!("./polyseed/ko.json");
const EN_WORDS: &str = include_str!("./polyseed/en.json");
const IT_WORDS: &str = include_str!("./polyseed/it.json");
const ES_WORDS: &str = include_str!("./polyseed/es.json");
const JA_WORDS: &str = include_str!("./polyseed/ja.json");
const PT_WORDS: &str = include_str!("./polyseed/pt.json");
const ZH_S_WORDS: &str = include_str!("./polyseed/zh_simp.json");
const ZH_T_WORDS: &str = include_str!("./polyseed/zh_trad.json");

lazy_static! {
  static ref LANGUAGES: HashMap<Language, WordList> = HashMap::from([
    (Language::Czech, WordList::new(CS_WORDS, true, false)),
    (Language::French, WordList::new(FR_WORDS, true, true)),
    (Language::Korean, WordList::new(KO_WORDS, false, false)),
    (Language::English, WordList::new(EN_WORDS, true, false)),
    (Language::Italian, WordList::new(IT_WORDS, true, false)),
    (Language::Spanish, WordList::new(ES_WORDS, true, true)),
    (Language::Japanese, WordList::new(JA_WORDS, false, false)),
    (Language::Portuguese, WordList::new(PT_WORDS, true, false)),
    (Language::ChineseSimplified, WordList::new(ZH_S_WORDS, false, false)),
    (Language::ChineseTraditional, WordList::new(ZH_T_WORDS, false, false)),
  ]);
}

struct PolyseedData {
  pub birthday: u64,
  pub features: u32,
  pub entropy: Zeroizing<[u8; 32]>,
  pub checksum: u16,
}

impl PolyseedData {
  /// creates a `PolyseedData` with current time birthday, random entropy and no features.
  pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> PolyseedData {
    // get birthday
    let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let birthday = birthday_encode(time);

    // make an entropy
    let mut entropy = Zeroizing::new([0; 32]);
    rng.fill_bytes(entropy.as_mut());
    entropy[SECRET_SIZE ..].fill(0);
    entropy[SECRET_SIZE - 1] &= CLEAR_MASK;

    // make the polyseed data
    let mut data = PolyseedData { birthday, features: 0, entropy, checksum: 0 };

    // set the  checksum
    data.checksum = create_checksum(&data);

    data
  }

  pub fn from(features: u32, birthday: u64, entropy: Zeroizing<[u8; 32]>) -> Option<PolyseedData> {
    // check features
    let features = make_features(features);
    if !polyseed_features_supported(features) {
      return None;
    }

    // get birthday
    let birthday = birthday_encode(birthday);

    // make sure it is a valid scalar.
    if !valid_entropy(&entropy) {
      return None;
    }

    // make the data
    let mut data = PolyseedData { birthday, features, entropy, checksum: 0 };

    // set the  checksum
    data.checksum = create_checksum(&data);

    Some(data)
  }
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct Polyseed(Zeroizing<String>);
impl Polyseed {
  /// returns a new seed for a given lang.
  pub fn new<R: RngCore + CryptoRng>(rng: &mut R, lang: Language) -> Polyseed {
    poly_encode(PolyseedData::new(rng), lang)
  }

  /// returns a new `Polyseed` for a given string.
  pub fn from_string(words: Zeroizing<String>) -> Result<Polyseed, SeedError> {
    let (data, lang) = poly_decode(&words)?;

    // Make sure this is a valid scalar
    if !valid_entropy(&data.entropy) {
      return Err(SeedError::PolyseedInvalidEntropy)?;
    }

    // Call from so a trimmed seed becomes a full seed
    Ok(Self::from(data.features, data.birthday, data.entropy, lang).unwrap())
  }

  /// returns a new `PolySeed` for a given `PolyseedData`.
  pub fn from(
    features: u32,
    birthday: u64,
    entropy: Zeroizing<[u8; 32]>,
    lang: Language,
  ) -> Option<Polyseed> {
    PolyseedData::from(features, birthday, entropy).map(|d| poly_encode(d, lang))
  }

  pub fn key(&self) -> Zeroizing<[u8; 32]> {
    let pass = poly_decode(&self.0).unwrap().0.entropy;
    let mut key: [u8; 32] = [0; 32];
    pbkdf2_hmac::<Sha3_256>(
      (*pass).as_slice(),
      POLYSEED_SALT.as_bytes(),
      POLYSEED_KEYGEN_ITERATIONS,
      &mut key[..],
    );
    Zeroizing::new(key)
  }

  pub(crate) fn to_string(&self) -> Zeroizing<String> {
    self.0.clone()
  }

  pub(crate) fn birthday(&self) -> u64 {
    poly_decode(&self.0).unwrap().0.birthday
  }

  pub(crate) fn entropy(&self) -> Zeroizing<[u8; 32]> {
    poly_decode(&self.0).unwrap().0.entropy
  }
}

fn poly_encode(data: PolyseedData, lang: Language) -> Polyseed {
  // encode polynomial with the existing checksum
  let mut poly = polyseed_data_to_poly(&data);
  poly[0] = data.checksum;

  // apply coin
  poly[POLY_NUM_CHECK_DIGITS] ^= COIN;

  // output words
  let mut seed = String::new();
  let words = &LANGUAGES[&lang].words;
  for i in 0 .. poly.len() {
    seed.push_str(&words[poly[i] as usize]);
    if i < poly.len() - 1 {
      seed.push(' ');
    }
  }

  Polyseed(Zeroizing::new(seed))
}

fn poly_decode(seed: &str) -> Result<(PolyseedData, Language), SeedError> {
  // decode words into polynomial coefficients
  let (mut poly, lang) = find_seed_language(seed)?;
  poly[POLY_NUM_CHECK_DIGITS] ^= COIN;

  // checksum
  if poly_eval(&poly) != 0 {
    Err(SeedError::PolyseedInvalidPoly)?;
  }

  // decode polynomial into seed data
  let data = poly_to_polyseed_data(poly);

  // check features
  if !polyseed_features_supported(data.features) {
    Err(SeedError::PolyseedFeatureNotSupported)?;
  }

  Ok((data, lang))
}

fn find_seed_language(seed: &str) -> Result<(Poly, Language), SeedError> {
  let mut indices: Poly = [0; POLYSEED_LENGTH];
  let seed_words: Vec<String> = seed.split_whitespace().map(|w| w.to_string()).collect();

  for (name, l) in LANGUAGES.iter() {
    let mut full_match = true;
    for (i, sw) in seed_words.iter().enumerate() {
      // find the word index
      let result = if l.has_prefix {
        if l.has_accent {
          l.words.iter().position(|w| {
            w.chars()
              .filter(|c| c.is_ascii())
              .collect::<String>()
              .starts_with(&sw.chars().filter(|c| c.is_ascii()).collect::<String>())
          })
        } else {
          l.words.iter().position(|w| w.starts_with(sw))
        }
      } else if l.has_accent {
        l.words.iter().position(|w| {
          w.chars()
            .filter(|c| c.is_ascii())
            .collect::<String>()
            .eq(&sw.chars().filter(|c| c.is_ascii()).collect::<String>())
        })
      } else {
        l.words.iter().position(|w| w == sw)
      };

      if let Some(idx) = result {
        indices[i] = idx as u16;
      } else {
        full_match = false;
        break;
      }
    }

    if full_match {
      return Ok((indices, *name));
    }
  }

  Err(SeedError::UnknownLanguage)?
}

fn polyseed_data_to_poly(data: &PolyseedData) -> Poly {
  let extra_val: u32 = (data.features << DATE_BITS) | (data.birthday as u32);
  let mut extra_bits: u32 = FEATURE_BITS + DATE_BITS;
  let mut word_bits: u32 = 0;
  let mut word_val: u32 = 0;
  let mut secret_idx: usize = 0;
  let mut secret_val: u32 = data.entropy[secret_idx] as u32;

  let mut secret_bits: u32 = CHAR_BIT;
  let mut seed_rem_bits: u32 = SECRET_BITS - CHAR_BIT;

  // create poly
  let mut poly: Poly = [0; POLYSEED_LENGTH];
  for i in 0 .. DATA_WORDS {
    while word_bits < SHARE_BITS {
      if secret_bits == 0 {
        secret_idx += 1;
        secret_bits = min(seed_rem_bits, CHAR_BIT);
        secret_val = data.entropy[secret_idx] as u32;
        seed_rem_bits -= secret_bits;
      }
      let chunk_bits: u32 = min(secret_bits, SHARE_BITS - word_bits);
      secret_bits -= chunk_bits;
      word_bits += chunk_bits;
      word_val <<= chunk_bits;
      word_val |= (secret_val >> secret_bits) & ((1 << chunk_bits) - 1);
    }
    word_val <<= 1;
    extra_bits -= 1;
    word_val |= (extra_val >> extra_bits) & 1;
    poly[POLY_NUM_CHECK_DIGITS + i] = word_val as u16;
    word_val = 0;
    word_bits = 0;
  }

  // TODO: Remove these after tests
  assert_eq!(seed_rem_bits, 0);
  assert_eq!(secret_bits, 0);
  assert_eq!(extra_bits, 0);

  poly
}

fn poly_to_polyseed_data(poly: Poly) -> PolyseedData {
  let mut entropy: [u8; 32] = [0; 32];
  let checksum = poly[0];

  let mut extra_val: u32 = 0;
  let mut extra_bits: u32 = 0;

  let mut word_bits: u32 = 0;

  let mut secret_idx: usize = 0;
  let mut secret_bits: u32 = 0;
  let mut seed_bits: u32 = 0;

  for val in poly.iter().skip(POLY_NUM_CHECK_DIGITS) {
    let mut word_val = u32::try_from(*val).unwrap();

    extra_val <<= 1;
    extra_val |= word_val & 1;
    word_val >>= 1;
    word_bits = GF_BITS - 1;
    extra_bits += 1;

    while word_bits > 0 {
      if secret_bits == CHAR_BIT {
        secret_idx += 1;
        seed_bits += secret_bits;
        secret_bits = 0;
      }
      let chunk_bits = min(word_bits, CHAR_BIT - secret_bits);
      word_bits -= chunk_bits;
      let chunk_mask = (1 << chunk_bits) - 1;
      if chunk_bits < CHAR_BIT {
        entropy[secret_idx] <<= chunk_bits;
      }
      entropy[secret_idx] |= ((word_val >> word_bits) & chunk_mask) as u8;
      secret_bits += chunk_bits;
    }
  }

  seed_bits += secret_bits;

  assert_eq!(word_bits, 0);
  assert_eq!(seed_bits, SECRET_BITS);
  assert_eq!(extra_bits, FEATURE_BITS + DATE_BITS);

  let birthday = extra_val & DATE_MASK;
  let features = extra_val >> DATE_BITS;

  PolyseedData {
    birthday: birthday_decode(birthday),
    features,
    entropy: Zeroizing::new(entropy),
    checksum,
  }
}

fn create_checksum(data: &PolyseedData) -> u16 {
  let poly = polyseed_data_to_poly(data);
  poly_eval(&poly)
}

fn elem_mul2(x: u16) -> u16 {
  if x < 1024 {
    return 2 * x;
  }
  POLYSEED_MUL2_TABLE[(x % 8) as usize] + 16 * ((x - 1024) / 8)
}

fn poly_eval(poly: &Poly) -> u16 {
  /* Horner's method at x = 2 */
  let mut result = poly[POLYSEED_LENGTH - 1];
  for i in (0 .. (POLYSEED_LENGTH - 1)).rev() {
    result = elem_mul2(result) ^ poly[i];
  }
  result
}

fn make_features(features: u32) -> u32 {
  features & USER_FEATURES_MASK
}

fn polyseed_features_supported(features: u32) -> bool {
  (features & RESERVED_FEATURES) == 0
}

fn birthday_encode(time: u64) -> u64 {
  ((time - EPOCH) / TIME_STEP) & (DATE_MASK as u64)
}

fn birthday_decode(birthday: u32) -> u64 {
  EPOCH + (birthday as u64) * TIME_STEP
}

fn valid_entropy(entropy: &Zeroizing<[u8; 32]>) -> bool {
  // Last 13 byte should be 0.
  for i in SECRET_SIZE .. entropy.len() {
    if entropy[i] != 0 {
      return false;
    }
  }
  true
}
