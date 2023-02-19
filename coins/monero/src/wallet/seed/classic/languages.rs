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
pub fn all() -> Result<HashMap<LanguageName, Language>, SeedError> {
  #[derive(serde::Deserialize)]
  struct Lang {
    name: String,
    unique_prefix_length: usize,
  }

  let mut langs = HashMap::new();
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
    let lang = match lang_name {
      LanguageName::EnglishOld => {
        Language::new(serde_json::from_str(words).unwrap(), l.unique_prefix_length, true, true)?
      }
      LanguageName::Spanish => {
        Language::new(serde_json::from_str(words).unwrap(), l.unique_prefix_length, true, false)?
      }
      _ => {
        Language::new(serde_json::from_str(words).unwrap(), l.unique_prefix_length, false, false)?
      }
    };

    langs.insert(lang_name, lang);
  }

  Ok(langs)
}
