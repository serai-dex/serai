#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::fmt::Debug;

use frost::sign::PreprocessMachine;

use scheduler::SignableTransaction;

pub(crate) mod db;

mod transaction;

/// An object capable of publishing a transaction.
#[async_trait::async_trait]
pub trait TransactionPublisher<S: SignableTransaction>: 'static + Send + Sync {
  /// An error encountered when publishing a transaction.
  ///
  /// This MUST be an ephemeral error. Retrying publication MUST eventually resolve without manual
  /// intervention/changing the arguments.
  type EphemeralError: Debug;

  /// Publish a transaction.
  ///
  /// This will be called multiple times, with the same transaction, until the transaction is
  /// confirmed on-chain.
  ///
  /// The transaction already being present in the mempool/on-chain MUST NOT be considered an
  /// error.
  async fn publish(
    &self,
    tx: <S::PreprocessMachine as PreprocessMachine>::Signature,
  ) -> Result<(), Self::EphemeralError>;
}

/*
// The signers used by a Processor, key-scoped.
struct KeySigners<D: Db, T: Clone + PreprocessMachine> {
  transaction: AttemptManager<D, T>,
  substrate: AttemptManager<D, AlgorithmMachine<Ristretto, Schnorrkel>>,
  cosigner: AttemptManager<D, AlgorithmMachine<Ristretto, Schnorrkel>>,
}

/// The signers used by a protocol.
pub struct Signers<D: Db, T: Clone + PreprocessMachine>(HashMap<Vec<u8>, KeySigners<D, T>>);

impl<D: Db, T: Clone + PreprocessMachine> Signers<D, T> {
  /// Create a new set of signers.
  pub fn new(db: D) -> Self {
    // TODO: Load the registered keys
    // TODO: Load the transactions being signed
    // TODO: Load the batches being signed
    todo!("TODO")
  }

  /// Register a transaction to sign.
  pub fn sign_transaction(&mut self) -> Vec<ProcessorMessage> {
    todo!("TODO")
  }
  /// Mark a transaction as signed.
  pub fn signed_transaction(&mut self) { todo!("TODO") }

  /// Register a batch to sign.
  pub fn sign_batch(&mut self, key: KeyFor<S>, batch: Batch) -> Vec<ProcessorMessage> {
    todo!("TODO")
  }
  /// Mark a batch as signed.
  pub fn signed_batch(&mut self, batch: u32) { todo!("TODO") }

  /// Register a slash report to sign.
  pub fn sign_slash_report(&mut self) -> Vec<ProcessorMessage> {
    todo!("TODO")
  }
  /// Mark a slash report as signed.
  pub fn signed_slash_report(&mut self) { todo!("TODO") }

  /// Start a cosigning protocol.
  pub fn cosign(&mut self) { todo!("TODO") }

  /// Handle a message for a signing protocol.
  pub fn handle(&mut self, msg: CoordinatorMessage) -> Vec<ProcessorMessage> {
    todo!("TODO")
  }
}
*/
