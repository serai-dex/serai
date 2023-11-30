use std::sync::Arc;

pub use ::parity_db::{Options, Db as ParityDb};

use crate::*;

pub struct Transaction<'a>(&'a Arc<ParityDb>, Vec<(u8, Vec<u8>, Option<Vec<u8>>)>);

impl Get for Transaction<'_> {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    let mut res = self.0.get(&key);
    for change in &self.1 {
      if change.1 == key.as_ref() {
        res = change.2.clone();
      }
    }
    res
  }
}
impl DbTxn for Transaction<'_> {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    self.1.push((0, key.as_ref().to_vec(), Some(value.as_ref().to_vec())))
  }
  fn del(&mut self, key: impl AsRef<[u8]>) {
    self.1.push((0, key.as_ref().to_vec(), None))
  }
  fn commit(self) {
    self.0.commit(self.1).unwrap()
  }
}

impl Get for Arc<ParityDb> {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    ParityDb::get(self, 0, key.as_ref()).unwrap()
  }
}
impl Db for Arc<ParityDb> {
  type Transaction<'a> = Transaction<'a>;
  fn txn(&mut self) -> Self::Transaction<'_> {
    Transaction(self, vec![])
  }
}

pub fn new_parity_db(path: &str) -> Arc<ParityDb> {
  Arc::new(ParityDb::open_or_create(&Options::with_columns(std::path::Path::new(path), 1)).unwrap())
}
