use std::{
  sync::{Arc, RwLock},
  collections::HashMap,
};

use crate::{DbTxn, Db};

#[derive(Clone, Debug)]
pub struct MemDb(Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>);
impl MemDb {
  pub(crate) fn new() -> MemDb {
    MemDb(Arc::new(RwLock::new(HashMap::new())))
  }
}
impl Default for MemDb {
  fn default() -> MemDb {
    MemDb::new()
  }
}

impl DbTxn for MemDb {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    self.0.write().unwrap().insert(key.as_ref().to_vec(), value.as_ref().to_vec());
  }
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    self.0.read().unwrap().get(key.as_ref()).cloned()
  }
  fn del(&mut self, key: impl AsRef<[u8]>) {
    self.0.write().unwrap().remove(key.as_ref());
  }
  fn commit(self) {}
}

impl Db for MemDb {
  type Transaction = MemDb;
  fn txn(&mut self) -> MemDb {
    Self(self.0.clone())
  }
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    self.0.read().unwrap().get(key.as_ref()).cloned()
  }
}
