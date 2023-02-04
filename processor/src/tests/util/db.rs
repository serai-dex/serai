use std::collections::HashMap;

use crate::Db;

pub(crate) struct MemDb(HashMap<Vec<u8>, Vec<u8>>);
impl MemDb {
  pub(crate) fn new() -> MemDb {
    MemDb(HashMap::new())
  }
}
impl Default for MemDb {
  fn default() -> MemDb {
    MemDb::new()
  }
}

impl Db for MemDb {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    self.0.insert(key.as_ref().to_vec(), value.as_ref().to_vec());
  }
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    self.0.get(key.as_ref()).cloned()
  }
}
