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
  fn put(&mut self, key: &[u8], value: &[u8]) {
    self.0.insert(key.to_vec(), value.to_vec());
  }
  fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
    self.0.get(key).cloned()
  }
}
