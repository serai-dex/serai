#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{fmt::Debug, marker::PhantomData};

use zeroize::Zeroizing;

use serai_validator_sets_primitives::Session;

use ciphersuite::{group::GroupEncoding, Ristretto};
use frost::dkg::{ThresholdCore, ThresholdKeys};

use serai_db::{DbTxn, Db};

use scheduler::{Transaction, SignableTransaction, TransactionsToSign};

pub(crate) mod db;

mod transaction;

/// An object capable of publishing a transaction.
#[async_trait::async_trait]
pub trait TransactionPublisher<T: Transaction>: 'static + Send + Sync {
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
  async fn publish(&self, tx: T) -> Result<(), Self::EphemeralError>;
}

/// The signers used by a processor.
pub struct Signers<ST: SignableTransaction>(PhantomData<ST>);

/*
  This is completely outside of consensus, so the worst that can happen is:

  1) Leakage of a private key, hence the usage of frost-attempt-manager which has an API to ensure
     that doesn't happen
  2) The database isn't perfectly cleaned up (leaving some bytes on disk wasted)
  3) The state isn't perfectly cleaned up (leaving some bytes in RAM wasted)

  The last two are notably possible via a series of race conditions. For example, if an Eventuality
  completion comes in *before* we registered a key, the signer will hold the signing protocol in
  memory until the session is retired entirely.
*/
impl<ST: SignableTransaction> Signers<ST> {
  /// Initialize the signers.
  ///
  /// This will spawn tasks for any historically registered keys.
  pub fn new(db: impl Db) -> Self {
    for session in db::RegisteredKeys::get(&db).unwrap_or(vec![]) {
      let buf = db::SerializedKeys::get(&db, session).unwrap();
      let mut buf = buf.as_slice();

      let mut substrate_keys = vec![];
      let mut external_keys = vec![];
      while !buf.is_empty() {
        substrate_keys
          .push(ThresholdKeys::from(ThresholdCore::<Ristretto>::read(&mut buf).unwrap()));
        external_keys
          .push(ThresholdKeys::from(ThresholdCore::<ST::Ciphersuite>::read(&mut buf).unwrap()));
      }

      todo!("TODO")
    }

    todo!("TODO")
  }

  /// Register a set of keys to sign with.
  ///
  /// If this session (or a session after it) has already been retired, this is a NOP.
  pub fn register_keys(
    &mut self,
    txn: &mut impl DbTxn,
    session: Session,
    substrate_keys: Vec<ThresholdKeys<Ristretto>>,
    network_keys: Vec<ThresholdKeys<ST::Ciphersuite>>,
  ) {
    if Some(session.0) <= db::LatestRetiredSession::get(txn).map(|session| session.0) {
      return;
    }

    {
      let mut sessions = db::RegisteredKeys::get(txn).unwrap_or_else(|| Vec::with_capacity(1));
      sessions.push(session);
      db::RegisteredKeys::set(txn, &sessions);
    }

    {
      let mut buf = Zeroizing::new(Vec::with_capacity(2 * substrate_keys.len() * 128));
      for (substrate_keys, network_keys) in substrate_keys.into_iter().zip(network_keys) {
        buf.extend(&*substrate_keys.serialize());
        buf.extend(&*network_keys.serialize());
      }
      db::SerializedKeys::set(txn, session, &buf);
    }
  }

  /// Retire the signers for a session.
  ///
  /// This MUST be called in order, for every session (even if we didn't register keys for this
  /// session).
  pub fn retire_session(
    &mut self,
    txn: &mut impl DbTxn,
    session: Session,
    external_key: &impl GroupEncoding,
  ) {
    // Update the latest retired session
    {
      let next_to_retire =
        db::LatestRetiredSession::get(txn).map_or(Session(0), |session| Session(session.0 + 1));
      assert_eq!(session, next_to_retire);
      db::LatestRetiredSession::set(txn, &session);
    }

    // Kill the tasks
    todo!("TODO");

    // Update RegisteredKeys/SerializedKeys
    if let Some(registered) = db::RegisteredKeys::get(txn) {
      db::RegisteredKeys::set(
        txn,
        &registered.into_iter().filter(|session_i| *session_i != session).collect(),
      );
    }
    db::SerializedKeys::del(txn, session);

    // Drain the transactions to sign
    // Presumably, TransactionsToSign will be fully populated before retiry occurs, making this
    // perfect in not leaving any pending blobs behind
    while TransactionsToSign::<ST>::try_recv(txn, external_key).is_some() {}

    // Drain our DB channels
    while db::CompletedEventualitiesForEachKey::try_recv(txn, session).is_some() {}
    while db::CoordinatorToTransactionSignerMessages::try_recv(txn, session).is_some() {}
    while db::TransactionSignerToCoordinatorMessages::try_recv(txn, session).is_some() {}
    while db::CoordinatorToBatchSignerMessages::try_recv(txn, session).is_some() {}
    while db::BatchSignerToCoordinatorMessages::try_recv(txn, session).is_some() {}
    while db::CoordinatorToSlashReportSignerMessages::try_recv(txn, session).is_some() {}
    while db::SlashReportSignerToCoordinatorMessages::try_recv(txn, session).is_some() {}
    while db::CoordinatorToCosignerMessages::try_recv(txn, session).is_some() {}
    while db::CosignerToCoordinatorMessages::try_recv(txn, session).is_some() {}
  }
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
