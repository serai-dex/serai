mod mem;
pub use mem::*;

#[cfg(feature = "rocksdb")]
mod rocks;

/// An object implementing get.
pub trait Get {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>>;
}

/// An atomic database operation.
#[must_use]
pub trait DbTxn: Send + Get {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>);
  fn del(&mut self, key: impl AsRef<[u8]>);
  fn commit(self);
}

/// A database supporting atomic operations.
pub trait Db: 'static + Send + Sync + Clone + Get {
  type Transaction<'a>: DbTxn;
  fn key(db_dst: &'static [u8], item_dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    let db_len = u8::try_from(db_dst.len()).unwrap();
    let dst_len = u8::try_from(item_dst.len()).unwrap();
    [[db_len].as_ref(), db_dst, [dst_len].as_ref(), item_dst, key.as_ref()].concat()
  }
  fn txn(&mut self) -> Self::Transaction<'_>;
}
