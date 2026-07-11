use alloc::sync::Arc;

use rocksdb::{
  DBCompressionType, SingleThreaded, LogLevel, WriteOptions, Transaction as RocksTransaction,
  Options, OptimisticTransactionDB,
};

use crate::{Get, Db};

/// A transaction for a RocksDB database.
pub struct Transaction<'db> {
  db: &'db OptimisticTransactionDB<SingleThreaded>,
  txn: RocksTransaction<'db, OptimisticTransactionDB<SingleThreaded>>,
}

impl Get for Transaction<'_> {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<impl AsRef<[u8]>> {
    self.txn.get(key).expect("couldn't read from RocksDB via transaction")
  }
}
impl crate::Transaction for Transaction<'_> {
  fn set(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    self.txn.put(key, value).expect("couldn't write to RocksDB via transaction");
  }
  fn del(&mut self, key: impl AsRef<[u8]>) {
    self.txn.delete(key).expect("couldn't delete from RocksDB via transaction");
  }
  fn commit(self) {
    self.txn.commit().expect("couldn't commit to RocksDB via transaction");
    self.db.flush_wal(true).expect("couldn't flush RocksDB WAL");
    self.db.flush().expect("couldn't flush RocksDB");
  }
}

impl Get for Arc<OptimisticTransactionDB<SingleThreaded>> {
  fn get(&self, key: impl AsRef<[u8]>) -> Option<impl AsRef<[u8]>> {
    OptimisticTransactionDB::get(self, key).expect("couldn't read from RocksDB")
  }
}
impl Db for Arc<OptimisticTransactionDB<SingleThreaded>> {
  type Transaction<'db> = Transaction<'db>;
  fn txn(&mut self) -> Self::Transaction<'_> {
    let mut opts = WriteOptions::default();
    opts.set_sync(true);
    Transaction { db: self, txn: self.transaction_opt(&opts, &Default::default()) }
  }
}

/// The RocksDB database type.
pub type RocksDB = Arc<OptimisticTransactionDB<SingleThreaded>>;

/// Open a RocksDB database.
///
/// This will create the database if it does not already exist.
///
/// This will panic if opening/creating the database errors.
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

  Arc::new(OptimisticTransactionDB::open(&options, path).expect("failed to create/open RocksDB DB"))
}
