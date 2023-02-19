use std::{collections::HashMap, str};

use rand_core::{RngCore, CryptoRng};

use lazy_static::lazy_static;

use crc::{Crc, CRC_32_ISO_HDLC};
use zeroize::Zeroizing;

use crate::random_scalar;

use super::{SeedError, LanguageName};

// language words
const DUTCH_WORDS: &str = include_str!("./words/nl.json");
const GERMAN_WORDS: &str = include_str!("./words/de.json");
const FRENCH_WORDS: &str = include_str!("./words/fr.json");
const LOJBAN_WORDS: &str = include_str!("./words/jbo.json");
const ENGLISH_WORDS: &str = include_str!("./words/en.json");
const ITALIAN_WORDS: &str = include_str!("./words/it.json");
const SPANISH_WORDS: &str = include_str!("./words/es.json");
const RUSSIAN_WORDS: &str = include_str!("./words/ru.json");
const CHINESE_WORDS: &str = include_str!("./words/zh.json");
const JAPANESE_WORDS: &str = include_str!("./words/ja.json");
const ESPERANTO_WORDS: &str = include_str!("./words/eo.json");
const ENGLISHOLD_WORDS: &str = include_str!("./words/ang.json");
const PORTUGUESE_WORDS: &str = include_str!("./words/pt.json");

lazy_static! {
  pub static ref LANGUAGES: HashMap<LanguageName, Language> = HashMap::from([
    (LanguageName::Dutch, Language::new(serde_json::from_str(DUTCH_WORDS).unwrap(), 4)),
    (LanguageName::German, Language::new(serde_json::from_str(GERMAN_WORDS).unwrap(), 4)),
    (LanguageName::French, Language::new(serde_json::from_str(FRENCH_WORDS).unwrap(), 4)),
    (LanguageName::Lojban, Language::new(serde_json::from_str(LOJBAN_WORDS).unwrap(), 4)),
    (LanguageName::English, Language::new(serde_json::from_str(ENGLISH_WORDS).unwrap(), 3)),
    (LanguageName::Italian, Language::new(serde_json::from_str(ITALIAN_WORDS).unwrap(), 4)),
    (LanguageName::Spanish, Language::new(serde_json::from_str(SPANISH_WORDS).unwrap(), 4)),
    (LanguageName::Russian, Language::new(serde_json::from_str(RUSSIAN_WORDS).unwrap(), 4)),
    (LanguageName::Chinese, Language::new(serde_json::from_str(CHINESE_WORDS).unwrap(), 1)),
    (LanguageName::Japanese, Language::new(serde_json::from_str(JAPANESE_WORDS).unwrap(), 3)),
    (LanguageName::Esperanto, Language::new(serde_json::from_str(ESPERANTO_WORDS).unwrap(), 4)),
    (LanguageName::Portuguese, Language::new(serde_json::from_str(PORTUGUESE_WORDS).unwrap(), 4)),
    (LanguageName::EnglishOld, Language::new(serde_json::from_str(ENGLISHOLD_WORDS).unwrap(), 4)),
  ]);
}

pub const CLASSIC_SEED_LENGTH: usize = 24;
pub const CLASSIC_SEED_LENGTH_WITH_CHECKSUM: usize = 25;

#[derive(Clone)]
pub struct Language {
  word_list: Vec<String>,
  word_map: HashMap<String, usize>,
  trimmed_word_map: HashMap<String, usize>,
  unique_prefix_length: usize,
}

impl Language {
  /// creates a new language from words.
  fn new(words: Vec<String>, prefix_length: usize) -> Language {
    let mut lang = Language {
      word_list: words,
      word_map: HashMap::new(),
      trimmed_word_map: HashMap::new(),
      unique_prefix_length: prefix_length,
    };

    // populate maps
    for (i, word) in lang.word_list.iter().enumerate() {
      lang.word_map.insert(word.clone(), i);

      let trimmed = if word.len() > lang.unique_prefix_length {
        utf8_prefix(word, lang.unique_prefix_length)
      } else {
        word.clone()
      };

      lang.trimmed_word_map.insert(trimmed, i);
    }

    lang
  }
}

/// returns a new seed for a given lang.
pub fn new<R: RngCore + CryptoRng>(lang: LanguageName, rng: &mut R) -> Zeroizing<String> {
  let spend = random_scalar(rng);
  bytes_to_words(spend.as_bytes(), lang)
}

pub fn words_to_bytes(seed: &str) -> Result<Zeroizing<[u8; 32]>, SeedError> {
  // get seed words
  let seed_words: Vec<String> = seed.split_whitespace().map(|w| w.to_string()).collect();
  let seed_length = seed_words.len();
  if seed_length != CLASSIC_SEED_LENGTH && seed_length != CLASSIC_SEED_LENGTH_WITH_CHECKSUM {
    Err(SeedError::InvalidSeedLength)?;
  }

  // find the language
  let has_checksum = seed_length == CLASSIC_SEED_LENGTH_WITH_CHECKSUM;
  let (matched_indices, lang) = find_seed_language(&seed_words, has_checksum)?;

  // convert to  bytes
  let mut result: [u8; 32] = [0; 32];
  let word_list_len = lang.word_list.len();
  for i in 0 .. 8 {
    // read 3 indices at a time
    let mut indices: [usize; 4] = [0; 4];
    indices[1] = matched_indices[i * 3];
    indices[2] = matched_indices[i * 3 + 1];
    indices[3] = matched_indices[i * 3 + 2];

    // set the last index
    indices[0] = indices[1] +
      (word_list_len * (((word_list_len - indices[1]) + indices[2]) % word_list_len)) +
      (word_list_len *
        (word_list_len * (((word_list_len - indices[2]) + indices[3]) % word_list_len)));

    if indices[0] % word_list_len != indices[1] {
      Err(SeedError::InvalidSeed)?;
    }

    let pos = i * 4;
    result[pos .. pos + 4].copy_from_slice(&u32::try_from(indices[0]).unwrap().to_le_bytes());
  }

  Ok(Zeroizing::new(result))
}

pub fn bytes_to_words(key: &[u8; 32], lang_name: LanguageName) -> Zeroizing<String> {
  // Grab the language
  let lang = &LANGUAGES[&lang_name];

  // get the language words
  let words = &lang.word_list;
  let word_list_length = u32::try_from(words.len()).unwrap();

  // To store the found words & add the checksum word later.
  let mut result = vec![];

  // convert to words
  // 4 bytes -> 3 words. 8 digits base 16 -> 3 digits base 1626
  for i in 0 .. 8 {
    let mut indices: [u32; 4] = [0; 4];
    // convert first 4 byte to u32 & get the word indices
    let start = i * 4;
    // convert 4 byte to u32
    indices[0] = u32::from_le_bytes(key[start .. start + 4].try_into().unwrap());
    indices[1] = indices[0] % word_list_length;
    indices[2] = (indices[0] / word_list_length + indices[1]) % word_list_length;
    indices[3] =
      (((indices[0] / word_list_length) / word_list_length) + indices[2]) % word_list_length;

    // append words to seed
    result.push(words[indices[1] as usize].clone());
    result.push(words[indices[2] as usize].clone());
    result.push(words[indices[3] as usize].clone());
  }

  // create a checksum word for all langues except with old english
  if lang_name != LanguageName::EnglishOld {
    let checksum_index = create_checksum_index(&result, lang);
    result.push(result[checksum_index].clone());
  }

  Zeroizing::new(result.join(" "))
}

/// takes a seed and returns the code for matching language
fn find_seed_language(
  seed: &[String],
  has_checksum: bool,
) -> Result<(Vec<usize>, Language), SeedError> {
  let mut matched_indices = vec![];

  // Iterate through all the languages
  for (lang_name, lang) in LANGUAGES.iter() {
    let word_map = &lang.word_map;
    let trimmed_map = &lang.trimmed_word_map;

    // Iterate through all the words and see if they're all present
    let mut full_match = true;
    for w in seed {
      if has_checksum {
        let trimmed_word = utf8_prefix(w, lang.unique_prefix_length);
        if !trimmed_map.contains_key(&trimmed_word) {
          full_match = false;
          break;
        }
        matched_indices.push(trimmed_map[&trimmed_word]);
      } else {
        if !word_map.contains_key(w) {
          full_match = false;
          break;
        }
        matched_indices.push(word_map[w]);
      }
    }

    if full_match && has_checksum {
      if lang_name == &LanguageName::EnglishOld {
        Err(SeedError::EnglishOldWithChecksum)?;
      }

      if !checksum_test(seed, lang) {
        full_match = false;
      }
    }

    if full_match {
      return Ok((matched_indices, lang.clone()));
    }

    // no match for this language clear the indices
    matched_indices.clear();
  }

  Err(SeedError::UnknownLanguage)?
}

fn utf8_prefix(word: &str, prefix_len: usize) -> String {
  word.chars().take(prefix_len).collect()
}

fn create_checksum_index(words: &[String], lang: &Language) -> usize {
  let mut trimmed_words = String::new();

  for w in words {
    trimmed_words.push_str(utf8_prefix(w, lang.unique_prefix_length).as_str());
  }

  let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
  let mut digest = crc.digest();
  digest.update(trimmed_words.as_bytes());

  (digest.finalize() as usize) % words.len()
}

fn checksum_test(seed: &[String], lang: &Language) -> bool {
  if seed.is_empty() {
    return false;
  }

  // exclude the last word when calculating a checksum.
  let last_word = seed.last().unwrap().clone();
  let checksum_index = create_checksum_index(&seed[.. seed.len() - 1], lang);
  let checksum = seed[checksum_index].clone();

  // get the trimmed checksum and trimmed last word
  let trimmed_checksum = if checksum.len() > lang.unique_prefix_length {
    utf8_prefix(&checksum, lang.unique_prefix_length)
  } else {
    checksum
  };
  let trimmed_last_word = if last_word.len() > lang.unique_prefix_length {
    utf8_prefix(&last_word, lang.unique_prefix_length)
  } else {
    last_word
  };

  // check if they are equal
  if trimmed_checksum != trimmed_last_word {
    return false;
  }

  true
}
