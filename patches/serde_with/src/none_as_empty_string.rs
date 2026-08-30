use core::{str::FromStr, fmt::Display};
extern crate alloc;
use alloc::string::{String, ToString as _};

use super::*;

/// A semantic equivalivent to [`serde_with::NoneAsEmptyString`](
///   https://docs.rs/serde_with/3/serde_with/struct.NoneAsEmptyString.html
/// ), as necessary within Serai's dependency tree.
///
/// This is a lossy representation as a value which stringifies as "", or can be created from the
/// string "", will be interpreted as `None`. This is NOT recommended for use accordingly and is
/// only present here as necessary for Serai to compile.
pub struct NoneAsEmptyString;

impl<V: Display> SerializeWrapper<Option<V>> for NoneAsEmptyString {
  fn serialize<S>(
    value: &Option<V>,
    serializer: S,
  ) -> Result<<S as serde::Serializer>::Ok, <S as serde::Serializer>::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_str(&match value.as_ref() {
      Some(value) => value.to_string(),
      None => String::new(),
    })
  }
}

impl<V: FromStr<Err: Display>> DeserializeWrapper<Option<V>> for NoneAsEmptyString {
  fn deserialize<'de, D>(
    deserializer: D,
  ) -> Result<Option<V>, <D as serde::Deserializer<'de>>::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let string = <String as serde::Deserialize<'de>>::deserialize(deserializer)?;
    if string.is_empty() {
      return Ok(None);
    }
    <V as FromStr>::from_str(&string)
      .map(Some)
      .map_err(<<D as serde::Deserializer<'de>>::Error as serde::de::Error>::custom)
  }
}
