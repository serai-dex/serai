use core::ops::Deref;
use std::collections::HashMap;

use lazy_static::lazy_static;

use zeroize::{Zeroize, Zeroizing};
use rand_core::{RngCore, CryptoRng};

use crc::{Crc, CRC_32_ISO_HDLC};

use curve25519_dalek::scalar::Scalar;

use crate::{
  random_scalar,
  wallet::seed::{SeedError, Language},
};

pub(crate) const CLASSIC_SEED_LENGTH: usize = 24;
pub(crate) const CLASSIC_SEED_LENGTH_WITH_CHECKSUM: usize = 25;

fn trim(word: &str, len: usize) -> Zeroizing<String> {
  Zeroizing::new(word.chars().take(len).collect())
}

struct WordList {
  word_list: Vec<&'static str>,
  word_map: HashMap<&'static str, usize>,
  trimmed_word_map: HashMap<String, usize>,
  unique_prefix_length: usize,
}

impl WordList {
  fn new(word_list: Vec<&'static str>, prefix_length: usize) -> WordList {
    let mut lang = WordList {
      word_list,
      word_map: HashMap::new(),
      trimmed_word_map: HashMap::new(),
      unique_prefix_length: prefix_length,
    };

    for (i, word) in lang.word_list.iter().enumerate() {
      lang.word_map.insert(word, i);
      lang.trimmed_word_map.insert(trim(word, lang.unique_prefix_length).deref().clone(), i);
    }

    lang
  }
}

lazy_static! {
  static ref LANGUAGES: HashMap<Language, WordList> = HashMap::from([
    (Language::Chinese, WordList::new(include!("./classic/zh.rs"), 1)),
    (Language::English, WordList::new(include!("./classic/en.rs"), 3)),
    (Language::Dutch, WordList::new(include!("./classic/nl.rs"), 4)),
    (Language::French, WordList::new(include!("./classic/fr.rs"), 4)),
    (Language::Spanish, WordList::new(include!("./classic/es.rs"), 4)),
    (Language::German, WordList::new(include!("./classic/de.rs"), 4)),
    (Language::Italian, WordList::new(include!("./classic/it.rs"), 4)),
    (Language::Portuguese, WordList::new(include!("./classic/pt.rs"), 4)),
    (Language::Japanese, WordList::new(include!("./classic/ja.rs"), 3)),
    (Language::Russian, WordList::new(include!("./classic/ru.rs"), 4)),
    (Language::Esperanto, WordList::new(include!("./classic/eo.rs"), 4)),
    (Language::Lojban, WordList::new(include!("./classic/jbo.rs"), 4)),
    (Language::EnglishOld, WordList::new(include!("./classic/ang.rs"), 4)),
  ]);
}

#[cfg(test)]
pub(crate) fn trim_by_lang(word: &str, lang: Language) -> String {
  if lang != Language::EnglishOld {
    word.chars().take(LANGUAGES[&lang].unique_prefix_length).collect()
  } else {
    word.to_string()
  }
}

fn checksum_index(words: &[Zeroizing<String>], lang: &WordList) -> usize {
  let mut trimmed_words = Zeroizing::new(String::new());
  for w in words {
    *trimmed_words += &trim(w, lang.unique_prefix_length);
  }

  let crc = Crc::<u32>::new(&CRC_32_ISO_HDLC);
  let mut digest = crc.digest();
  digest.update(trimmed_words.as_bytes());

  usize::try_from(digest.finalize()).unwrap() % words.len()
}

// Convert a private key to a seed
fn key_to_seed(lang: Language, key: Zeroizing<Scalar>) -> ClassicSeed {
  let bytes = Zeroizing::new(key.to_bytes());

  // get the language words
  let words = &LANGUAGES[&lang].word_list;
  let list_len = u64::try_from(words.len()).unwrap();

  // To store the found words & add the checksum word later.
  let mut seed = Vec::with_capacity(25);

  // convert to words
  // 4 bytes -> 3 words. 8 digits base 16 -> 3 digits base 1626
  let mut segment = [0; 4];
  let mut indices = [0; 4];
  for i in 0 .. 8 {
    // convert first 4 byte to u32 & get the word indices
    let start = i * 4;
    // convert 4 byte to u32
    segment.copy_from_slice(&bytes[start .. (start + 4)]);
    // Actually convert to a u64 so we can add without overflowing
    indices[0] = u64::from(u32::from_le_bytes(segment));
    indices[1] = indices[0];
    indices[0] /= list_len;
    indices[2] = indices[0] + indices[1];
    indices[0] /= list_len;
    indices[3] = indices[0] + indices[2];

    // append words to seed
    for i in indices.iter().skip(1) {
      let word = usize::try_from(i % list_len).unwrap();
      seed.push(Zeroizing::new(words[word].to_string()));
    }
  }
  segment.zeroize();
  indices.zeroize();

  // create a checksum word for all languages except old english
  if lang != Language::EnglishOld {
    let checksum = seed[checksum_index(&seed, &LANGUAGES[&lang])].clone();
    seed.push(checksum);
  }

  let mut res = Zeroizing::new(String::new());
  for (i, word) in seed.iter().enumerate() {
    if i != 0 {
      *res += " ";
    }
    *res += word;
  }
  ClassicSeed(res)
}

// Convert a seed to bytes
pub(crate) fn seed_to_bytes(words: &str) -> Result<(Language, Zeroizing<[u8; 32]>), SeedError> {
  // get seed words
  let words = words.split_whitespace().map(|w| Zeroizing::new(w.to_string())).collect::<Vec<_>>();
  if (words.len() != CLASSIC_SEED_LENGTH) && (words.len() != CLASSIC_SEED_LENGTH_WITH_CHECKSUM) {
    panic!("invalid seed passed to seed_to_bytes");
  }

  // find the language
  let (matched_indices, lang_name, lang) = (|| {
    let has_checksum = words.len() == CLASSIC_SEED_LENGTH_WITH_CHECKSUM;
    let mut matched_indices = Zeroizing::new(vec![]);

    // Iterate through all the languages
    'language: for (lang_name, lang) in LANGUAGES.iter() {
      matched_indices.zeroize();
      matched_indices.clear();

      // Iterate through all the words and see if they're all present
      for word in &words {
        let trimmed = trim(word, lang.unique_prefix_length);
        let word = if has_checksum { &trimmed } else { word };

        if let Some(index) = if has_checksum {
          lang.trimmed_word_map.get(word.deref())
        } else {
          lang.word_map.get(&word.as_str())
        } {
          matched_indices.push(*index);
        } else {
          continue 'language;
        }
      }

      if has_checksum {
        if lang_name == &Language::EnglishOld {
          Err(SeedError::EnglishOldWithChecksum)?;
        }

        // exclude the last word when calculating a checksum.
        let last_word = words.last().unwrap().clone();
        let checksum = words[checksum_index(&words[.. words.len() - 1], lang)].clone();

        // check the trimmed checksum and trimmed last word line up
        if trim(&checksum, lang.unique_prefix_length) != trim(&last_word, lang.unique_prefix_length)
        {
          Err(SeedError::InvalidChecksum)?;
        }
      }

      return Ok((matched_indices, lang_name, lang));
    }

    Err(SeedError::UnknownLanguage)?
  })()?;

  // convert to bytes
  let mut res = Zeroizing::new([0; 32]);
  let mut indices = Zeroizing::new([0; 4]);
  for i in 0 .. 8 {
    // read 3 indices at a time
    let i3 = i * 3;
    indices[1] = matched_indices[i3];
    indices[2] = matched_indices[i3 + 1];
    indices[3] = matched_indices[i3 + 2];

    let inner = |i| {
      let mut base = (lang.word_list.len() - indices[i] + indices[i + 1]) % lang.word_list.len();
      // Shift the index over
      for _ in 0 .. i {
        base *= lang.word_list.len();
      }
      base
    };
    // set the last index
    indices[0] = indices[1] + inner(1) + inner(2);
    if (indices[0] % lang.word_list.len()) != indices[1] {
      Err(SeedError::InvalidSeed)?;
    }

    let pos = i * 4;
    let mut bytes = u32::try_from(indices[0]).unwrap().to_le_bytes();
    res[pos .. (pos + 4)].copy_from_slice(&bytes);
    bytes.zeroize();
  }

  Ok((*lang_name, res))
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct ClassicSeed(Zeroizing<String>);
impl ClassicSeed {
  pub(crate) fn new<R: RngCore + CryptoRng>(rng: &mut R, lang: Language) -> ClassicSeed {
    key_to_seed(lang, Zeroizing::new(random_scalar(rng)))
  }

  pub fn from_string(words: Zeroizing<String>) -> Result<ClassicSeed, SeedError> {
    let (lang, entropy) = seed_to_bytes(&words)?;

    // Make sure this is a valid scalar
    let mut scalar = Scalar::from_canonical_bytes(*entropy);
    if scalar.is_none() {
      Err(SeedError::InvalidSeed)?;
    }
    scalar.zeroize();

    // Call from_entropy so a trimmed seed becomes a full seed
    Ok(Self::from_entropy(lang, entropy).unwrap())
  }

  pub fn from_entropy(lang: Language, entropy: Zeroizing<[u8; 32]>) -> Option<ClassicSeed> {
    Scalar::from_canonical_bytes(*entropy).map(|scalar| key_to_seed(lang, Zeroizing::new(scalar)))
  }

  pub(crate) fn to_string(&self) -> Zeroizing<String> {
    self.0.clone()
  }

  pub(crate) fn entropy(&self) -> Zeroizing<[u8; 32]> {
    seed_to_bytes(&self.0).unwrap().1
  }
}
