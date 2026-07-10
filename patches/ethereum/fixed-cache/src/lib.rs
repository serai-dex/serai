#![no_std]

use core::marker::PhantomData;

pub struct Cache<Key, Value, Hasher, Config>(PhantomData<(Key, Value, Hasher, Config)>);
impl<Key, Value, Hasher, Config> Cache<Key, Value, Hasher, Config> {
  pub fn new(_entries: usize, _hasher: Hasher) -> Self {
    Self(PhantomData)
  }
  pub fn get_or_insert_with_ref<'key>(
    &self,
    key: &'key Key,
    value: impl FnOnce(&'key Key) -> Value,
    _key_alias_to_key: impl FnOnce(&'key Key) -> Key,
  ) -> Value {
    value(key)
  }
}
