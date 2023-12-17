use core::fmt::Debug;
use std::{
  sync::{Arc, RwLock},
  collections::{HashSet, HashMap},
};

use crate::*;

/// An atomic operation for the in-memory database.
#[must_use]
#[derive(PartialEq, Eq, Debug)]
pub struct MemDbTxn<'a>(&'a MemDb, HashMap<Vec<u8>, Vec<u8>>, HashSet<Vec<u8>>);

impl<'a> Get for MemDbTxn<'a> {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    if self.2.contains(key.as_ref()) {
      return None;
    }
    self
      .1
      .get(key.as_ref())
      .cloned()
      .or_else(|| self.0 .0.read().unwrap().get(key.as_ref()).cloned())
  }
}
impl<'a> DbTxn for MemDbTxn<'a> {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    self.2.remove(key.as_ref());
    self.1.insert(key.as_ref().to_vec(), value.as_ref().to_vec());
  }
  fn del(&mut self, key: impl AsRef<[u8]>) {
    self.1.remove(key.as_ref());
    self.2.insert(key.as_ref().to_vec());
  }
  fn commit(mut self) {
    let mut db = self.0 .0.write().unwrap();
    for (key, value) in self.1.drain() {
      db.insert(key, value);
    }
    for key in self.2 {
      db.remove(&key);
    }
  }
}

/// An in-memory database.
#[derive(Clone, Debug)]
pub struct MemDb(Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>);

impl PartialEq for MemDb {
  fn eq(&self, other: &MemDb) -> bool {
    *self.0.read().unwrap() == *other.0.read().unwrap()
  }
}
impl Eq for MemDb {}

impl Default for MemDb {
  fn default() -> MemDb {
    MemDb(Arc::new(RwLock::new(HashMap::new())))
  }
}

impl MemDb {
  /// Create a new in-memory database.
  pub fn new() -> MemDb {
    MemDb::default()
  }
}

impl Get for MemDb {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    self.0.read().unwrap().get(key.as_ref()).cloned()
  }
}
impl Db for MemDb {
  type Transaction<'a> = MemDbTxn<'a>;
  fn txn(&mut self) -> MemDbTxn<'_> {
    MemDbTxn(self, HashMap::new(), HashSet::new())
  }
}
