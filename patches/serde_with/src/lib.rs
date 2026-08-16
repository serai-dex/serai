#![no_std]

use core::marker::PhantomData;

#[doc(hidden)]
pub use serde;

pub use serde_with_macros::*;

#[cfg(feature = "alloc")]
mod none_as_empty_string;
#[cfg(feature = "alloc")]
pub use none_as_empty_string::*;

#[cfg(feature = "base64")]
pub mod base64;

trait SerializeWrapper<V> {
  fn serialize<S>(
    value: &V,
    serializer: S,
  ) -> Result<<S as serde::Serializer>::Ok, <S as serde::Serializer>::Error>
  where
    S: serde::Serializer;
}

trait DeserializeWrapper<V> {
  fn deserialize<'de, D>(deserializer: D) -> Result<V, <D as serde::Deserializer<'de>>::Error>
  where
    D: serde::Deserializer<'de>;
}

/// A semantic equivalivent to [`serde_with::As`](
///   https://docs.rs/serde_with/3/serde_with/struct.As.html
/// ), as necessary within Serai's dependency tree.
pub struct As<T>(PhantomData<T>);
#[expect(private_bounds)]
impl<T> As<T> {
  /// Serialize the value `V` with the semantics applied by this type `T`.
  ///
  /// Per [`serde_with`'s documentation](https://docs.rs/serde_with/3/serde_with/struct.As.html),
  /// this has the necessary structure to allow [`As`] to be used as
  /// `#[serde(with = "::serde_with::As<T>")]`.
  pub fn serialize<V, S>(
    value: &V,
    serializer: S,
  ) -> Result<<S as serde::Serializer>::Ok, <S as serde::Serializer>::Error>
  where
    T: SerializeWrapper<V>,
    S: serde::Serializer,
  {
    <T as SerializeWrapper<V>>::serialize(value, serializer)
  }

  /// Deserialize the value `V` with the semantics applied by this type `T`.
  ///
  /// Per [`serde_with`'s documentation](https://docs.rs/serde_with/3/serde_with/struct.As.html),
  /// this has the necessary structure to allow [`As`] to be used as
  /// `#[serde(with = "::serde_with::As<T>")]`.
  pub fn deserialize<'de, V, D>(
    deserializer: D,
  ) -> Result<V, <D as serde::Deserializer<'de>>::Error>
  where
    T: DeserializeWrapper<V>,
    D: serde::Deserializer<'de>,
  {
    <T as DeserializeWrapper<V>>::deserialize(deserializer)
  }
}

impl<V, T: SerializeWrapper<V>> SerializeWrapper<Option<V>> for Option<T> {
  fn serialize<S>(
    value: &Option<V>,
    serializer: S,
  ) -> Result<<S as serde::Serializer>::Ok, <S as serde::Serializer>::Error>
  where
    S: serde::Serializer,
  {
    /*
      Instead of manually implementing `Serialize` to accomplish this, we use `serde`'s provided
      derivation macro to simplify our code in this patch, even if this is slower to compile and
      less efficient.

      The inner value is a borrow to ensure we don't have to clone the value passed to us by
      reference.
    */
    #[derive(serde::Serialize)]
    #[serde(transparent)]
    #[repr(transparent)]
    struct Wrapper<'value, V, T: SerializeWrapper<V>> {
      #[serde(with = "As::<T>")]
      value: &'value V,
      #[serde(skip)]
      _phantom: PhantomData<T>,
    }

    match value {
      Some(value) => serializer.serialize_some(&Wrapper { value, _phantom: PhantomData::<T> }),
      None => serializer.serialize_none(),
    }
  }
}

impl<V, T: DeserializeWrapper<V>> DeserializeWrapper<Option<V>> for Option<T> {
  fn deserialize<'de, D>(
    deserializer: D,
  ) -> Result<Option<V>, <D as serde::Deserializer<'de>>::Error>
  where
    D: serde::Deserializer<'de>,
  {
    /*
      This complements the wrapper inside the `SerializeWrapper<Option<V>> for Option<T>`
      implementation, but with an owned value, as needed for deserialization.
    */
    #[derive(serde::Deserialize)]
    #[serde(transparent)]
    #[repr(transparent)]
    struct Wrapper<V, T: DeserializeWrapper<V>> {
      #[serde(with = "As::<T>")]
      value: V,
      #[serde(skip)]
      _phantom: PhantomData<T>,
    }

    Ok(
      <Option<Wrapper<V, T>> as serde::Deserialize>::deserialize(deserializer)?
        .map(|wrapper| wrapper.value),
    )
  }
}
