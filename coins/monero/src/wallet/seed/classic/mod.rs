use std::collections::HashMap;

use crc::{Crc, CRC_32_ISO_HDLC};
use rand_core::OsRng;

use crate::random_scalar;

use super::{SeedError, LanguageName};

mod languages;

pub const CLASSIC_SEED_LENGTH: usize = 24;
pub const CLASSIC_SEED_LENGTH_WITH_CHECKSUM: usize = 25;
const LANGUAGE_WORD_COUNT: usize = 1626;

#[derive(Clone)]
pub struct Language {
  word_list: Vec<String>,
  word_map: HashMap<String, usize>,
  trimmed_word_map: HashMap<String, usize>,
  language_name: LanguageName,
  unique_prefix_length: usize,
}

impl Language {
  /// populates the word_map and trimmed_word_maps
  fn populate_maps(
    &mut self,
    allow_short_words: bool,
    allow_duplicate_prefix: bool,
  ) -> Result<(), SeedError> {
    if self.word_list.len() != LANGUAGE_WORD_COUNT {
      Err(SeedError::InvalidLanguageWordList)?;
    }

    for (i, word) in self.word_list.iter().enumerate() {
      self.word_map.insert(word.clone(), i);

      if word.len() < self.unique_prefix_length && !allow_short_words {
        Err(SeedError::InvalidWordInLanguage)?;
      }

      let trimmed = if word.len() > self.unique_prefix_length {
        utf8_prefix(word, self.unique_prefix_length)
      } else {
        word.to_string()
      };

      if self.trimmed_word_map.contains_key(&trimmed) && !allow_duplicate_prefix {
        Err(SeedError::DuplicatePrefix)?;
      }

      self.trimmed_word_map.insert(trimmed, i);
    }

    Ok(())
  }
}

/// returns a new seed for a given lang.
pub fn new(lang: LanguageName) -> Result<String, SeedError> {
  let spend = random_scalar(&mut OsRng);
  bytes_to_words(spend.as_bytes(), lang)
}

pub fn words_to_bytes(seed: &str) -> Result<[u8; 32], SeedError> {
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
  let mut result: [u8; 32] = [b'0'; 32];
  let word_list_len = lang.word_list.len();
  for i in 0 .. 8 {
    let mut indices: [usize; 4] = [0; 4];
    indices[1] = matched_indices[i * 3];
    indices[2] = matched_indices[i * 3 + 1];
    indices[3] = matched_indices[i * 3 + 2];

    indices[0] = indices[1] +
      word_list_len * (((word_list_len - indices[1]) + indices[2]) % word_list_len) +
      word_list_len *
        word_list_len *
        (((word_list_len - indices[2]) + indices[3]) % word_list_len);

    if indices[0] % word_list_len != indices[1] {
      Err(SeedError::InvalidSeed)?;
    }

    let pos = i * 4;
    result[pos .. pos + 4].copy_from_slice(&(indices[0] as u32).to_le_bytes());
  }

  Ok(result)
}

pub fn bytes_to_words(key: &[u8; 32], lang_name: LanguageName) -> Result<String, SeedError> {
  // Grab the language, we can call unwrap because all language names must exist.
  let lang = languages::all()?.into_iter().find(|l| l.language_name == lang_name).unwrap();

  // get the language words
  let words = &lang.word_list;
  let word_list_length = words.len() as u32;

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
  let checksum_index = create_checksum_index(&result, &lang)?;
  result.push(result[checksum_index].clone());

  Ok(result.join(" "))
}

/// takes a seed and returns the code for matching language
fn find_seed_language(
  seed: &[String],
  has_checksum: bool,
) -> Result<(Vec<usize>, Language), SeedError> {
  let lang_list = languages::all()?;
  let mut matched_indices = vec![];
  let matched_language: Language;

  for lang in &lang_list {
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

    if full_match && has_checksum && !checksum_test(seed, lang)? {
      full_match = false;
    }

    if full_match {
      matched_language = lang.clone();
      return Ok((matched_indices, matched_language));
    }

    // no match for this language clear the indices
    matched_indices.clear();
  }

  Err(SeedError::UnknownLanguage)?
}

fn utf8_prefix(word: &str, mut prefix_len: usize) -> String {
  let mut prefix = String::new();
  for a in word.chars() {
    if (a as u8) & 0xc0 == 0x80 {
      prefix.push(a);
      continue;
    }
    prefix.push(a);
    prefix_len -= 1;

    if prefix_len == 0 {
      break;
    }
  }
  prefix
}

fn create_checksum_index(words: &[String], lang: &Language) -> Result<usize, SeedError> {
  let mut trimmed_words = String::new();

  for w in words {
    let word = utf8_prefix(w, lang.unique_prefix_length);
    if !lang.trimmed_word_map.contains_key(&word) {
      Err(SeedError::UnknownPrefix)?;
    }
    trimmed_words.push_str(word.as_str());
  }

  let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
  let mut digest = crc.digest();
  digest.update(trimmed_words.as_bytes());

  Ok((digest.finalize() as usize) % words.len())
}

fn checksum_test(seed: &[String], lang: &Language) -> Result<bool, SeedError> {
  if seed.is_empty() {
    return Ok(false);
  }

  // exclude the last word when calculating a checksum.
  let last_word = seed.last().unwrap().clone();
  let checksum_index = create_checksum_index(&seed[.. seed.len() - 1], lang)?;
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
    return Ok(false);
  }

  Ok(true)
}
