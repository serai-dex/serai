use core::{marker::PhantomData, fmt::Debug};
use std::{
  sync::{Arc, RwLock},
  collections::HashMap,
};

use crate::{Plan, coins::Coin};

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

#[derive(Debug)]
pub struct MainDb<C: Coin, D: Db>(D, PhantomData<C>);
impl<C: Coin, D: Db> MainDb<C, D> {
  pub fn new(db: D) -> Self {
    Self(db, PhantomData)
  }

  fn main_key(dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    D::key(b"MAIN", dst, key)
  }

  fn plan_key(id: &[u8]) -> Vec<u8> {
    Self::main_key(b"plan", id)
  }
  fn signing_key(key: &[u8]) -> Vec<u8> {
    Self::main_key(b"signing", key)
  }
  pub fn save_signing(&mut self, key: &[u8], block_number: u64, time: u64, plan: &Plan<C>) {
    let id = plan.id();
    // Creating a TXN here is arguably an anti-pattern, yet nothing here expects atomicity
    let mut txn = self.0.txn();

    {
      let mut signing = txn.get(Self::signing_key(key)).unwrap_or(vec![]);

      // If we've already noted we're signing this, return
      assert_eq!(signing.len() % 32, 0);
      for i in 0 .. (signing.len() / 32) {
        if signing[(i * 32) .. ((i + 1) * 32)] == id {
          return;
        }
      }

      signing.extend(&id);
      txn.put(Self::signing_key(key), id);
    }

    {
      let mut buf = block_number.to_le_bytes().to_vec();
      buf.extend(&time.to_le_bytes());
      plan.write(&mut buf).unwrap();
      txn.put(Self::plan_key(&id), &buf);
    }

    txn.commit();
  }

  pub fn signing(&self, key: &[u8]) -> Vec<(u64, u64, Plan<C>)> {
    let signing = self.0.get(Self::signing_key(key)).unwrap_or(vec![]);
    let mut res = vec![];

    assert_eq!(signing.len() % 32, 0);
    for i in 0 .. (signing.len() / 32) {
      let id = &signing[(i * 32) .. ((i + 1) * 32)];
      let buf = self.0.get(Self::plan_key(id)).unwrap();

      let block_number = u64::from_le_bytes(buf[.. 8].try_into().unwrap());
      let time = u64::from_le_bytes(buf[8 .. 16].try_into().unwrap());
      let plan = Plan::<C>::read::<&[u8]>(&mut &buf[16 ..]).unwrap();
      assert_eq!(id, &plan.id());
      res.push((block_number, time, plan));
    }

    res
  }
}
