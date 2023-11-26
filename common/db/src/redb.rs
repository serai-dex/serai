use std::sync::Arc;

pub use ::redb::Database as Redb;
use ::redb::*;

use crate::*;

impl Get for WriteTransaction<'_> {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    let table = self.open_table::<&[u8], Vec<u8>>(TableDefinition::new("default")).unwrap();
    table.get(key.as_ref()).unwrap().map(|value| value.value().to_vec())
  }
}
impl DbTxn for WriteTransaction<'_> {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    let mut table = self.open_table::<&[u8], &[u8]>(TableDefinition::new("default")).unwrap();
    table.insert(key.as_ref(), value.as_ref()).unwrap();
  }
  fn del(&mut self, key: impl AsRef<[u8]>) {
    let mut table = self.open_table::<&[u8], Vec<u8>>(TableDefinition::new("default")).unwrap();
    table.remove(key.as_ref()).unwrap();
  }
  fn commit(self) {
    self.commit().unwrap()
  }
}

impl Get for Arc<Redb> {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    let txn = self.begin_read().unwrap();
    let Ok(table) = txn.open_table::<&[u8], Vec<u8>>(TableDefinition::new("default")) else {
      return None;
    };
    table.get(key.as_ref()).unwrap().map(|value| value.value().to_vec())
  }
}
impl Db for Arc<Redb> {
  type Transaction<'a> = WriteTransaction<'a>;
  fn txn(&mut self) -> Self::Transaction<'_> {
    self.begin_write().unwrap()
  }
}

pub fn new_redb(path: &str) -> Arc<Redb> {
  Arc::new(Redb::create(path).unwrap())
}
