use std::sync::Arc;

use rocksdb::{
  DBCompressionType, ThreadMode, SingleThreaded, LogLevel, WriteOptions,
  Transaction as RocksTransaction, Options, OptimisticTransactionDB,
};

use crate::*;

#[must_use]
pub struct Transaction<'a, T: ThreadMode>(
  RocksTransaction<'a, OptimisticTransactionDB<T>>,
  &'a OptimisticTransactionDB<T>,
);

impl<T: ThreadMode> Get for Transaction<'_, T> {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    self.0.get(key).expect("couldn't read from RocksDB via transaction")
  }
}
impl<T: ThreadMode> DbTxn for Transaction<'_, T> {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    self.0.put(key, value).expect("couldn't write to RocksDB via transaction")
  }
  fn del(&mut self, key: impl AsRef<[u8]>) {
    self.0.delete(key).expect("couldn't delete from RocksDB via transaction")
  }
  fn commit(self) {
    self.0.commit().expect("couldn't commit to RocksDB via transaction");
    self.1.flush_wal(true).expect("couldn't flush RocksDB WAL");
    self.1.flush().expect("couldn't flush RocksDB");
  }
}

impl<T: ThreadMode> Get for Arc<OptimisticTransactionDB<T>> {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    OptimisticTransactionDB::get(self, key).expect("couldn't read from RocksDB")
  }
}
impl<T: Send + ThreadMode + 'static> Db for Arc<OptimisticTransactionDB<T>> {
  type Transaction<'a> = Transaction<'a, T>;
  fn txn(&mut self) -> Self::Transaction<'_> {
    let mut opts = WriteOptions::default();
    opts.set_sync(true);
    Transaction(self.transaction_opt(&opts, &Default::default()), &**self)
  }
}

pub type RocksDB = Arc<OptimisticTransactionDB<SingleThreaded>>;
pub fn new_rocksdb(path: &str) -> RocksDB {
  let mut options = Options::default();
  options.create_if_missing(true);
  options.set_compression_type(DBCompressionType::Zstd);

  options.set_wal_compression_type(DBCompressionType::Zstd);
  // 10 MB
  options.set_max_total_wal_size(10 * 1024 * 1024);
  options.set_wal_size_limit_mb(10);

  options.set_log_level(LogLevel::Warn);
  // 1 MB
  options.set_max_log_file_size(1024 * 1024);
  options.set_recycle_log_file_num(1);

  Arc::new(OptimisticTransactionDB::open(&options, path).unwrap())
}
