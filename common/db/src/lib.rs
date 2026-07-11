#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

#[doc(hidden)]
pub mod __private {
  #[cfg(feature = "schema")]
  pub use borsh;
}
#[cfg(feature = "schema")]
mod schema;

#[cfg(feature = "std")]
mod mem;
#[cfg(feature = "std")]
pub use mem::*;

#[cfg(feature = "rocksdb")]
mod rocks;
#[cfg(feature = "rocksdb")]
pub use rocks::{RocksDB, new_rocksdb};

#[cfg(feature = "parity-db")]
mod parity_db;
#[cfg(feature = "parity-db")]
pub use parity_db::{ParityDb, new_parity_db};

/// A handle to an ACID database via which values may be read.
pub trait Get {
  /// Get a value from the database.
  ///
  /// If the key is not present in the database, this will return `None`.
  ///
  /// The implementation MAY panic if the database is corrupt or would become corrupted.
  fn get(&self, key: impl AsRef<[u8]>) -> Option<impl AsRef<[u8]>>;
}

/// An ACID transaction.
///
/// This transaction implements [`Get`]. If this transaction has queued a write to a key, the
/// retrieved value for that key will be the latest value queued to be written by this transaction.
/// If this transaction has not queued a write to a key, it's undefined if the retrieved value is
/// either:
/// A) The value which was written to the key _when the transaction was opened_
/// B) The value which is _currently_ written to the key (which may have been modified by a
///    concurrent transaction)
pub trait Transaction: Send + Get {
  /// Write a value to this key.
  ///
  /// If a concurrent transaction has queued a write to this key, the database MAY panic or exhibit
  /// an undefined choice of which transaction's queued write resolves as the database's current
  /// value for this key.
  ///
  /// The implementation MAY panic if the database is corrupt or would become corrupted.
  fn set(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>);
  /// Delete the value from this key.
  ///
  /// This is considered as a write to this key, with properties as documented by
  /// [`Transaction::put`].
  ///
  /// The implementation MAY panic if the database is corrupt or would become corrupted.
  fn del(&mut self, key: impl AsRef<[u8]>);
  /// Commit this transaction.
  ///
  /// The implementation MAY panic if the database is corrupt or would become corrupted.
  fn commit(self);
}

/// A handle to an ACID database.
///
/// This implements [`Clone`] on the expectation clones refer to the same underlying database. This
/// effectively makes this a reference-counted handle to the underlying database.
///
/// This implements [`Get`], allowing reading the current values in the database without having to
/// open a transaction.
pub trait Db: Clone + Get {
  /// The type representing a database transaction.
  type Transaction<'db>: Transaction
  where
    Self: 'db;

  /// Open a new transaction.
  fn txn(&mut self) -> Self::Transaction<'_>;
}
