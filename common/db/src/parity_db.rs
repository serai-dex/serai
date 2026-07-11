use alloc::{sync::Arc, vec::Vec};
use std::{path::Path, collections::HashMap};

pub use ::parity_db::{Options, Db as ParityDb};

use crate::{Get, Db};

/// A transaction for a `parity-db` database.
pub struct Transaction<'db> {
  db: &'db Arc<ParityDb>,
  queued_changes: HashMap<Vec<u8>, Option<Vec<u8>>>,
}

impl Get for Transaction<'_> {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<impl AsRef<[u8]>> {
    match self.queued_changes.get(key.as_ref()) {
      Some(Some(value)) => Some(value.clone()),
      Some(None) => None?,
      None => self.db.get(key.as_ref()).map(|bytes| bytes.as_ref().to_vec()),
    }
  }
}

impl crate::Transaction for Transaction<'_> {
  fn set(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    self.queued_changes.insert(key.as_ref().to_vec(), Some(value.as_ref().to_vec()));
  }
  fn del(&mut self, key: impl AsRef<[u8]>) {
    self.queued_changes.insert(key.as_ref().to_vec(), None);
  }
  fn commit(self) {
    self
      .db
      .commit(
        self.queued_changes.into_iter().map(|(key, value)| (0, key, value)).collect::<Vec<_>>(),
      )
      .expect("failed to commit to `parity-db` DB");
  }
}

impl Get for Arc<ParityDb> {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<impl AsRef<[u8]>> {
    ParityDb::get(self, 0, key.as_ref()).expect("failed to get from `parity-db` DB")
  }
}
impl Db for Arc<ParityDb> {
  type Transaction<'db> = Transaction<'db>;
  fn txn(&mut self) -> Self::Transaction<'_> {
    Transaction { db: self, queued_changes: HashMap::new() }
  }
}

/// Open a `parity-db` database.
///
/// This will create the database if it does not already exist.
///
/// This will panic if opening/creating the database errors.
pub fn new_parity_db(path: &str) -> Arc<ParityDb> {
  Arc::new(
    ParityDb::open_or_create(&Options::with_columns(Path::new(path), 1))
      .expect("failed to open/create `parity-db` DB"),
  )
}
