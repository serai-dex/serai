use std::io;

use frost::ThresholdKeys;
use scheduler_test_primitives::*;
use serai_db::{Db as _, Transaction as _, MemDb};
use serai_processor_scheduler_primitives::{SignableTransaction, TransactionsToSign};
use dalek_ff_group::Ed25519;
use ciphersuite::WrappedGroup as _;

#[test]
fn round_trip() {
  let mut db = MemDb::new();
  let mut db_txn = db.txn();
  let key = Ed25519::generator();
  let tx = TestSignableTransaction([1; 32]);
  TransactionsToSign::<TestSignableTransaction>::send(&mut db_txn, &key, &tx);
  let received_tx =
    TransactionsToSign::<TestSignableTransaction>::try_recv(&mut db_txn, &key).unwrap();

  assert_eq!(tx, received_tx);
}

#[test]
fn empty_queue() {
  let mut db = MemDb::new();
  let mut db_txn = db.txn();
  let key = Ed25519::generator();
  let received_tx = TransactionsToSign::<TestSignableTransaction>::try_recv(&mut db_txn, &key);

  assert!(received_tx.is_none());
}

#[test]
fn fifo() {
  let mut db = MemDb::new();
  let mut db_txn = db.txn();
  let key = Ed25519::generator();

  for i in 0 .. 10 {
    let tx = TestSignableTransaction([i; 32]);
    TransactionsToSign::<TestSignableTransaction>::send(&mut db_txn, &key, &tx);
  }

  for i in 0 .. 10 {
    let received_tx =
      TransactionsToSign::<TestSignableTransaction>::try_recv(&mut db_txn, &key).unwrap();
    assert_eq!(TestSignableTransaction([i; 32]), received_tx);
  }

  // queue should be empty
  let received_tx = TransactionsToSign::<TestSignableTransaction>::try_recv(&mut db_txn, &key);
  assert!(received_tx.is_none());
}

#[test]
fn separate_keys_separate_queues() {
  let mut db = MemDb::new();
  let mut db_txn = db.txn();
  let key1 = Ed25519::generator();
  let key2 = key1 + key1;
  let tx = TestSignableTransaction([1; 32]);

  TransactionsToSign::<TestSignableTransaction>::send(&mut db_txn, &key1, &tx);

  let received_tx_key2 =
    TransactionsToSign::<TestSignableTransaction>::try_recv(&mut db_txn, &key2);
  assert!(received_tx_key2.is_none());

  let received_tx_key1 =
    TransactionsToSign::<TestSignableTransaction>::try_recv(&mut db_txn, &key1).unwrap();
  assert_eq!(tx, received_tx_key1);
}

#[test]
#[should_panic(expected = "assertion `left == right` failed")]
fn read_consuming_wrong_length_of_bytes_panics() {
  let mut db = MemDb::new();
  let mut db_txn = db.txn();
  let key = Ed25519::generator();
  let tx = TestSignableTransaction([1; 32]);

  TransactionsToSign::<TestSignableTransaction>::send(&mut db_txn, &key, &tx);
  TransactionsToSign::<TestSignableTransactionShortRead>::try_recv(&mut db_txn, &key).unwrap();
}

#[test]
fn written_tx_survives_commit() {
  let mut db = MemDb::new();
  let mut db_txn = db.txn();
  let key = Ed25519::generator();
  let tx = TestSignableTransaction([1; 32]);
  TransactionsToSign::<TestSignableTransaction>::send(&mut db_txn, &key, &tx);
  db_txn.commit();

  db_txn = db.txn();
  let received_tx =
    TransactionsToSign::<TestSignableTransaction>::try_recv(&mut db_txn, &key).unwrap();
  assert_eq!(tx, received_tx);
  db_txn.commit();
}

#[test]
fn received_tx_is_gone_after_commit() {
  let mut db = MemDb::new();
  let key = Ed25519::generator();
  let tx = TestSignableTransaction([1; 32]);

  let mut db_txn = db.txn();
  TransactionsToSign::<TestSignableTransaction>::send(&mut db_txn, &key, &tx);
  db_txn.commit();

  db_txn = db.txn();
  let _ = TransactionsToSign::<TestSignableTransaction>::try_recv(&mut db_txn, &key).unwrap();
  db_txn.commit();

  db_txn = db.txn();
  let received_tx = TransactionsToSign::<TestSignableTransaction>::try_recv(&mut db_txn, &key);
  assert!(received_tx.is_none());
}

#[test]
fn uncommitted_receive_keeps_tx() {
  let mut db = MemDb::new();
  let key = Ed25519::generator();
  let tx = TestSignableTransaction([1; 32]);

  let mut db_txn = db.txn();
  TransactionsToSign::<TestSignableTransaction>::send(&mut db_txn, &key, &tx);
  db_txn.commit();

  db_txn = db.txn();
  let _ = TransactionsToSign::<TestSignableTransaction>::try_recv(&mut db_txn, &key).unwrap();

  db_txn = db.txn();
  let received_tx =
    TransactionsToSign::<TestSignableTransaction>::try_recv(&mut db_txn, &key).unwrap();
  assert_eq!(tx, received_tx);
}

/// A test signable transaction that reads only 30 bytes
/// instead of TestSignableTransaction's 32 bytes.
#[derive(Clone)]
struct TestSignableTransactionShortRead(pub [u8; 30]);

impl SignableTransaction for TestSignableTransactionShortRead {
  type Transaction = TestTransaction;

  type Ciphersuite = Ed25519;

  type PreprocessMachine = TestPreprocessMachine;

  fn read(reader: &mut impl io::Read) -> io::Result<Self> {
    let mut buffer = [0u8; 30];
    reader.read_exact(&mut buffer)?;

    Ok(Self(buffer))
  }

  fn write(&self, writer: &mut impl io::Write) -> io::Result<()> {
    writer.write_all(&self.0)
  }

  fn id(&self) -> [u8; 32] {
    todo!()
  }

  fn sign(self, _keys: ThresholdKeys<Self::Ciphersuite>) -> Self::PreprocessMachine {
    todo!()
  }
}
