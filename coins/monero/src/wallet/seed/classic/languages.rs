use std::collections::HashMap;

use crate::wallet::seed::{SeedError, LanguageName};

use super::Language;

// languages
const LANGUAGES: &str = include_str!("./languages.json");

// language words
const DUTCH_WORDS: &str = include_str!("./words/nl.json");
const GERMAN_WORDS: &str = include_str!("./words/de.json");
const FRENCH_WORDS: &str = include_str!("./words/fr.json");
const LOJBAN_WORDS: &str = include_str!("./words/jbo.json");
const ENGLISH_WORDS: &str = include_str!("./words/en.json");
const ITALIAN_WORDS: &str = include_str!("./words/it.json");
const SPANISH_WORDS: &str = include_str!("./words/es.json");
const RUSSIAN_WORDS: &str = include_str!("./words/ru.json");
const JAPANESE_WORDS: &str = include_str!("./words/ja.json");
const ESPERANTO_WORDS: &str = include_str!("./words/eo.json");
const ENGLISH_OLD_WORDS: &str = include_str!("./words/ang.json");
const PORTUGUESE_WORDS: &str = include_str!("./words/pt.json");
const CHINESE_SIMPLIFIED_WORDS: &str = include_str!("./words/zh.json");

/// returns all supported languages.
pub fn all() -> Result<Vec<Language>, SeedError> {
  #[derive(serde::Deserialize)]
  struct Lang {
    name: String,
    unique_prefix_length: usize,
  }

  let mut langs = vec![];
  for l in serde_json::from_str::<Vec<Lang>>(LANGUAGES).unwrap() {
    let (lang_name, words) = match l.name.as_str() {
      "Dutch" => (LanguageName::Dutch, DUTCH_WORDS),
      "German" => (LanguageName::German, GERMAN_WORDS),
      "French" => (LanguageName::French, FRENCH_WORDS),
      "Lojban" => (LanguageName::Lojban, LOJBAN_WORDS),
      "English" => (LanguageName::English, ENGLISH_WORDS),
      "Italian" => (LanguageName::Italian, ITALIAN_WORDS),
      "Spanish" => (LanguageName::Spanish, SPANISH_WORDS),
      "Russian" => (LanguageName::Russian, RUSSIAN_WORDS),
      "Japanese" => (LanguageName::Japanese, JAPANESE_WORDS),
      "Esperanto" => (LanguageName::Esperanto, ESPERANTO_WORDS),
      "EnglishOld" => (LanguageName::EnglishOld, ENGLISH_OLD_WORDS),
      "Portuguese" => (LanguageName::Portuguese, PORTUGUESE_WORDS),
      "ChineseSimplified" => (LanguageName::ChineseSimplified, CHINESE_SIMPLIFIED_WORDS),
      _ => Err(SeedError::UnknownLanguage)?,
    };
    let mut lang = Language {
      word_list: serde_json::from_str::<Vec<String>>(words).unwrap(),
      word_map: HashMap::new(),
      trimmed_word_map: HashMap::new(),
      language_name: lang_name,
      unique_prefix_length: l.unique_prefix_length,
    };
    match lang.language_name {
      LanguageName::EnglishOld => lang.populate_maps(true, true)?,
      LanguageName::Spanish => lang.populate_maps(true, false)?,
      _ => lang.populate_maps(false, false)?,
    }
    langs.push(lang);
  }

  Ok(langs)
}
