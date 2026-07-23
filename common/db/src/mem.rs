use core::fmt::Debug;
use alloc::{sync::Arc, vec::Vec};
use std::{sync::RwLock, collections::HashMap};

use crate::{Get, Db};

/// A transaction for [`MemDb`].
#[must_use]
#[derive(PartialEq, Eq, Debug)]
pub struct MemDbTxn<'db> {
  db: &'db MemDb,
  queued_changes: HashMap<Vec<u8>, Option<Vec<u8>>>,
}

impl Get for MemDbTxn<'_> {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<impl AsRef<[u8]>> {
    match self.queued_changes.get(key.as_ref()) {
      Some(Some(value)) => Some(value.clone()),
      Some(None) => None?,
      None => self.db.get(key.as_ref()).map(|bytes| bytes.as_ref().to_vec()),
    }
  }
}

impl crate::Transaction for MemDbTxn<'_> {
  fn set(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    self.queued_changes.insert(key.as_ref().to_vec(), Some(value.as_ref().to_vec()));
  }
  fn del(&mut self, key: impl AsRef<[u8]>) {
    self.queued_changes.insert(key.as_ref().to_vec(), None);
  }
  fn commit(mut self) {
    let mut db = self.db.0.write().unwrap();
    for (key, value) in self.queued_changes.drain() {
      match value {
        Some(value) => {
          db.insert(key, value);
        }
        None => {
          db.remove(&key);
        }
      }
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
  fn get(&self, key: impl AsRef<[u8]>) -> Option<impl AsRef<[u8]>> {
    self.0.read().unwrap().get(key.as_ref()).cloned()
  }
}
impl Db for MemDb {
  type Transaction<'db> = MemDbTxn<'db>;
  fn txn(&mut self) -> MemDbTxn<'_> {
    MemDbTxn { db: self, queued_changes: HashMap::new() }
  }
}
