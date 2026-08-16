use core::fmt::Display;
extern crate alloc;
use alloc::{vec::Vec, string::String};

use ::base64::prelude::*;

use super::*;

/// A semantic equivalivent to [`serde_with::base64::Base64`](
///   https://docs.rs/serde_with/3/serde_with/base64/struct.Base64.html
/// ), as necessary within Serai's dependency tree.
pub struct Base64;

impl<V: AsRef<[u8]>> SerializeWrapper<V> for Base64 {
  fn serialize<S>(
    value: &V,
    serializer: S,
  ) -> Result<<S as serde::Serializer>::Ok, <S as serde::Serializer>::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_str(&BASE64_STANDARD.encode(value.as_ref()))
  }
}

impl<V: TryFrom<Vec<u8>, Error: Display>> DeserializeWrapper<V> for Base64 {
  fn deserialize<'de, D>(deserializer: D) -> Result<V, <D as serde::Deserializer<'de>>::Error>
  where
    D: serde::Deserializer<'de>,
  {
    let string = <String as serde::Deserialize<'de>>::deserialize(deserializer)?;
    let bytes = BASE64_STANDARD
      .decode(&string)
      .map_err(<<D as serde::Deserializer<'de>>::Error as serde::de::Error>::custom)?;
    <V as TryFrom<Vec<u8>>>::try_from(bytes)
      .map_err(<<D as serde::Deserializer<'de>>::Error as serde::de::Error>::custom)
  }
}
