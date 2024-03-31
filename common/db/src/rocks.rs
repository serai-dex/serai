use std::{sync::Arc, collections::HashSet};

use rocksdb::{
  DBCompressionType, ThreadMode, SingleThreaded, LogLevel, WriteOptions,
  Transaction as RocksTransaction, Options, OptimisticTransactionDB, SnapshotWithThreadMode,
};

use crate::*;

pub struct Transaction<'a, T: ThreadMode> {
  dirtied_keys: HashSet<Vec<u8>>,
  txn: RocksTransaction<'a, OptimisticTransactionDB<T>>,
  snapshot: SnapshotWithThreadMode<'a, OptimisticTransactionDB<T>>,
  db: &'a OptimisticTransactionDB<T>,
}

impl<T: ThreadMode> Get for Transaction<'_, T> {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    if self.dirtied_keys.contains(key.as_ref()) {
      return self.txn.get(key).expect("couldn't read from RocksDB via transaction");
    }
    self.snapshot.get(key).expect("couldn't read from RocksDB via snapshot")
  }
}
impl<T: ThreadMode> DbTxn for Transaction<'_, T> {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    self.dirtied_keys.insert(key.as_ref().to_vec());
    self.txn.put(key, value).expect("couldn't write to RocksDB via transaction")
  }
  fn del(&mut self, key: impl AsRef<[u8]>) {
    self.dirtied_keys.insert(key.as_ref().to_vec());
    self.txn.delete(key).expect("couldn't delete from RocksDB via transaction")
  }
  fn commit(self) {
    self.txn.commit().expect("couldn't commit to RocksDB via transaction");
    self.db.flush_wal(true).expect("couldn't flush RocksDB WAL");
    self.db.flush().expect("couldn't flush RocksDB");
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
    Transaction {
      dirtied_keys: HashSet::new(),
      txn: self.transaction_opt(&opts, &Default::default()),
      snapshot: self.snapshot(),
      db: &**self,
    }
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
