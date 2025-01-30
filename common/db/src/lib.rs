mod create_db;
pub use create_db::*;

mod mem;
pub use mem::*;

#[cfg(feature = "rocksdb")]
mod rocks;
#[cfg(feature = "rocksdb")]
pub use rocks::{RocksDB, new_rocksdb};

#[cfg(feature = "parity-db")]
mod parity_db;
#[cfg(feature = "parity-db")]
pub use parity_db::{ParityDb, new_parity_db};

/// An object implementing `get`.
pub trait Get {
  /// Get a value from the database.
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>>;
}

/// An atomic database transaction.
///
/// A transaction is only required to atomically commit. It is not required that two `Get` calls
/// made with the same transaction return the same result, if another transaction wrote to that
/// key.
///
/// If two transactions are created, and both write (including deletions) to the same key, behavior
/// is undefined. The transaction may block, deadlock, panic, overwrite one of the two values
/// randomly, or any other action, at time of write or at time of commit.
#[must_use]
pub trait DbTxn: Send + Get {
  /// Write a value to this key.
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>);
  /// Delete the value from this key.
  fn del(&mut self, key: impl AsRef<[u8]>);
  /// Commit this transaction.
  fn commit(self);
}

/// A database supporting atomic transaction.
pub trait Db: 'static + Send + Sync + Clone + Get {
  /// The type representing a database transaction.
  type Transaction<'a>: DbTxn;
  /// Calculate a key for a database entry.
  ///
  /// Keys are separated by the database, the item within the database, and the item's key itself.
  fn key(db_dst: &'static [u8], item_dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    let db_len = u8::try_from(db_dst.len()).unwrap();
    let dst_len = u8::try_from(item_dst.len()).unwrap();
    [[db_len].as_ref(), db_dst, [dst_len].as_ref(), item_dst, key.as_ref()].concat()
  }
  /// Open a new transaction.
  fn txn(&mut self) -> Self::Transaction<'_>;
}
