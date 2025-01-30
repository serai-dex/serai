#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::marker::PhantomData;
use std::io;

use ciphersuite::{group::GroupEncoding, Ciphersuite};
use frost::{dkg::ThresholdKeys, sign::PreprocessMachine};

use serai_db::DbTxn;

/// A transaction.
pub trait Transaction: Sized + Send {
  /// Read a `Transaction`.
  fn read(reader: &mut impl io::Read) -> io::Result<Self>;
  /// Write a `Transaction`.
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()>;
}

/// A signable transaction.
pub trait SignableTransaction: 'static + Sized + Send + Sync + Clone {
  /// The underlying transaction type.
  type Transaction: Transaction;
  /// The ciphersuite used to sign this transaction.
  type Ciphersuite: Ciphersuite;
  /// The preprocess machine for the signing protocol for this transaction.
  type PreprocessMachine: Clone + PreprocessMachine<Signature: Send + Into<Self::Transaction>>;

  /// Read a `SignableTransaction`.
  fn read(reader: &mut impl io::Read) -> io::Result<Self>;
  /// Write a `SignableTransaction`.
  fn write(&self, writer: &mut impl io::Write) -> io::Result<()>;

  /// The ID for this transaction.
  ///
  /// This is an internal ID arbitrarily definable so long as it's unique.
  ///
  /// This same ID MUST be returned by the Eventuality for this transaction.
  fn id(&self) -> [u8; 32];

  /// Sign this transaction.
  fn sign(self, keys: ThresholdKeys<Self::Ciphersuite>) -> Self::PreprocessMachine;
}

/// The transaction type for a SignableTransaction.
pub type TransactionFor<ST> = <ST as SignableTransaction>::Transaction;

mod db {
  use serai_db::{Get, DbTxn, create_db, db_channel};

  db_channel! {
    SchedulerPrimitives {
      TransactionsToSign: (key: &[u8]) -> Vec<u8>,
    }
  }
}

/// The transactions to sign, as scheduled by a Scheduler.
pub struct TransactionsToSign<T>(PhantomData<T>);
impl<T: SignableTransaction> TransactionsToSign<T> {
  /// Send a transaction to sign.
  pub fn send(txn: &mut impl DbTxn, key: &impl GroupEncoding, tx: &T) {
    let mut buf = Vec::with_capacity(128);
    tx.write(&mut buf).unwrap();
    db::TransactionsToSign::send(txn, key.to_bytes().as_ref(), &buf);
  }

  /// Try to receive a transaction to sign.
  pub fn try_recv(txn: &mut impl DbTxn, key: &impl GroupEncoding) -> Option<T> {
    let tx = db::TransactionsToSign::try_recv(txn, key.to_bytes().as_ref())?;
    let mut tx = tx.as_slice();
    let res = T::read(&mut tx).unwrap();
    assert!(tx.is_empty());
    Some(res)
  }
}
