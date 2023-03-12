use core::fmt::Debug;
use std::{
  sync::{Arc, RwLock},
  collections::HashMap,
};

pub trait DbTxn: Send + Sync + Clone + Debug {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>);
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>>;
  fn del(&mut self, key: impl AsRef<[u8]>);
  fn commit(self);
}

pub trait Db: 'static + Send + Sync + Clone + Debug {
  type Transaction: DbTxn;
  fn key(db_dst: &'static [u8], item_dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    let db_len = u8::try_from(db_dst.len()).unwrap();
    let dst_len = u8::try_from(item_dst.len()).unwrap();
    [[db_len].as_ref(), db_dst, [dst_len].as_ref(), item_dst, key.as_ref()].concat().to_vec()
  }
  fn txn(&mut self) -> Self::Transaction;
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>>;
}

// TODO: Replace this with RocksDB
#[derive(Clone, Debug)]
pub struct MemDb(Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>);
impl MemDb {
  #[allow(clippy::new_without_default)]
  pub fn new() -> MemDb {
    MemDb(Arc::new(RwLock::new(HashMap::new())))
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
