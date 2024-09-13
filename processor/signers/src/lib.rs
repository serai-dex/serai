#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{future::Future, fmt::Debug, marker::PhantomData};
use std::collections::HashMap;

use zeroize::Zeroizing;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use frost::dkg::{ThresholdCore, ThresholdKeys};

use serai_primitives::Signature;
use serai_validator_sets_primitives::{Session, Slash};
use serai_in_instructions_primitives::{Batch, SignedBatch};

use serai_db::{DbTxn, Db};

use messages::sign::{VariantSignId, ProcessorMessage, CoordinatorMessage};

use primitives::task::{Task, TaskHandle, ContinuallyRan};
use scheduler::{Transaction, SignableTransaction, TransactionFor};
use scanner::{ScannerFeed, Scheduler};

mod wrapped_schnorrkel;
pub(crate) use wrapped_schnorrkel::WrappedSchnorrkelMachine;

pub(crate) mod db;

mod coordinator;
use coordinator::CoordinatorTask;

mod cosign;
use cosign::CosignerTask;

mod batch;
use batch::BatchSignerTask;

mod slash_report;
use slash_report::SlashReportSignerTask;

mod transaction;
use transaction::TransactionSignerTask;

/// A connection to the Coordinator which messages can be published with.
pub trait Coordinator: 'static + Send + Sync {
  /// An error encountered when interacting with a coordinator.
  ///
  /// This MUST be an ephemeral error. Retrying an interaction MUST eventually resolve without
  /// manual intervention/changing the arguments.
  type EphemeralError: Debug;

  /// Send a `messages::sign::ProcessorMessage`.
  fn send(
    &mut self,
    message: ProcessorMessage,
  ) -> impl Send + Future<Output = Result<(), Self::EphemeralError>>;

  /// Publish a cosign.
  fn publish_cosign(
    &mut self,
    block_number: u64,
    block_id: [u8; 32],
    signature: Signature,
  ) -> impl Send + Future<Output = Result<(), Self::EphemeralError>>;

  /// Publish a `Batch`.
  fn publish_batch(
    &mut self,
    batch: Batch,
  ) -> impl Send + Future<Output = Result<(), Self::EphemeralError>>;

  /// Publish a `SignedBatch`.
  fn publish_signed_batch(
    &mut self,
    batch: SignedBatch,
  ) -> impl Send + Future<Output = Result<(), Self::EphemeralError>>;

  /// Publish a slash report's signature.
  fn publish_slash_report_signature(
    &mut self,
    session: Session,
    signature: Signature,
  ) -> impl Send + Future<Output = Result<(), Self::EphemeralError>>;
}

/// An object capable of publishing a transaction.
pub trait TransactionPublisher<T: Transaction>: 'static + Send + Sync + Clone {
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
  fn publish(&self, tx: T) -> impl Send + Future<Output = Result<(), Self::EphemeralError>>;
}

struct Tasks {
  cosigner: TaskHandle,
  batch: TaskHandle,
  slash_report: TaskHandle,
  transaction: TaskHandle,
}

/// The signers used by a processor.
#[allow(non_snake_case)]
pub struct Signers<
  D: Db,
  S: ScannerFeed,
  Sch: Scheduler<S>,
  P: TransactionPublisher<TransactionFor<SignableTransactionFor<S, Sch>>>,
> {
  db: D,
  publisher: P,
  coordinator_handle: TaskHandle,
  tasks: HashMap<Session, Tasks>,
  _Sch: PhantomData<Sch>,
  _S: PhantomData<S>,
}

type CiphersuiteFor<S, Sch> =
  <<Sch as Scheduler<S>>::SignableTransaction as SignableTransaction>::Ciphersuite;
type SignableTransactionFor<S, Sch> = <Sch as Scheduler<S>>::SignableTransaction;

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
impl<
    D: Db,
    S: ScannerFeed,
    Sch: Scheduler<S>,
    P: TransactionPublisher<TransactionFor<SignableTransactionFor<S, Sch>>>,
  > Signers<D, S, Sch, P>
{
  fn tasks(
    db: D,
    publisher: P,
    coordinator_handle: TaskHandle,
    session: Session,
    substrate_keys: Vec<ThresholdKeys<Ristretto>>,
    external_keys: Vec<ThresholdKeys<CiphersuiteFor<S, Sch>>>,
  ) -> Tasks {
    let (cosign_task, cosign_handle) = Task::new();
    tokio::spawn(
      CosignerTask::new(db.clone(), session, substrate_keys.clone())
        .continually_run(cosign_task, vec![coordinator_handle.clone()]),
    );

    let (batch_task, batch_handle) = Task::new();
    tokio::spawn(
      BatchSignerTask::new(
        db.clone(),
        session,
        external_keys[0].group_key(),
        substrate_keys.clone(),
      )
      .continually_run(batch_task, vec![coordinator_handle.clone()]),
    );

    let (slash_report_task, slash_report_handle) = Task::new();
    tokio::spawn(
      SlashReportSignerTask::<_, S>::new(db.clone(), session, substrate_keys)
        .continually_run(slash_report_task, vec![coordinator_handle.clone()]),
    );

    let (transaction_task, transaction_handle) = Task::new();
    tokio::spawn(
      TransactionSignerTask::<_, SignableTransactionFor<S, Sch>, _>::new(
        db,
        publisher,
        session,
        external_keys,
      )
      .continually_run(transaction_task, vec![coordinator_handle]),
    );

    Tasks {
      cosigner: cosign_handle,
      batch: batch_handle,
      slash_report: slash_report_handle,
      transaction: transaction_handle,
    }
  }
  /// Initialize the signers.
  ///
  /// This will spawn tasks for any historically registered keys.
  pub fn new(mut db: D, coordinator: impl Coordinator, publisher: P) -> Self {
    /*
      On boot, perform any database cleanup which was queued.

      We don't do this cleanup at time of dropping the task as we'd need to wait an unbounded
      amount of time for the task to stop (requiring an async task), then we'd have to drain the
      channels (which would be on a distinct DB transaction and risk not occurring if we rebooted
      while waiting for the task to stop). This is the easiest way to handle this.
    */
    {
      let mut txn = db.txn();
      for (session, external_key_bytes) in db::ToCleanup::get(&txn).unwrap_or(vec![]) {
        let mut external_key_bytes = external_key_bytes.as_slice();
        let external_key = CiphersuiteFor::<S, Sch>::read_G(&mut external_key_bytes).unwrap();
        assert!(external_key_bytes.is_empty());

        // Drain the Batches to sign
        // This will be fully populated by the scanner before retiry occurs, making this perfect
        // in not leaving any pending blobs behind
        while scanner::BatchesToSign::try_recv(&mut txn, &external_key).is_some() {}
        // Drain the acknowledged batches to no longer sign
        while scanner::AcknowledgedBatches::try_recv(&mut txn, &external_key).is_some() {}

        // Drain the transactions to sign
        // This will be fully populated by the scheduler before retiry
        while scheduler::TransactionsToSign::<SignableTransactionFor<S, Sch>>::try_recv(
          &mut txn,
          &external_key,
        )
        .is_some()
        {}

        // Drain the completed Eventualities
        while scanner::CompletedEventualities::try_recv(&mut txn, &external_key).is_some() {}

        // Delete the cosign this session should be working on
        db::ToCosign::del(&mut txn, session);
        // Drain our DB channels
        while db::Cosign::try_recv(&mut txn, session).is_some() {}
        while db::SlashReport::try_recv(&mut txn, session).is_some() {}
        while db::CoordinatorToCosignerMessages::try_recv(&mut txn, session).is_some() {}
        while db::CosignerToCoordinatorMessages::try_recv(&mut txn, session).is_some() {}
        while db::CoordinatorToBatchSignerMessages::try_recv(&mut txn, session).is_some() {}
        while db::BatchSignerToCoordinatorMessages::try_recv(&mut txn, session).is_some() {}
        while db::CoordinatorToSlashReportSignerMessages::try_recv(&mut txn, session).is_some() {}
        while db::SlashReportSignerToCoordinatorMessages::try_recv(&mut txn, session).is_some() {}
        while db::CoordinatorToTransactionSignerMessages::try_recv(&mut txn, session).is_some() {}
        while db::TransactionSignerToCoordinatorMessages::try_recv(&mut txn, session).is_some() {}
      }
      db::ToCleanup::del(&mut txn);
      txn.commit();
    }

    let mut tasks = HashMap::new();

    let (coordinator_task, coordinator_handle) = Task::new();
    tokio::spawn(
      CoordinatorTask::new(db.clone(), coordinator).continually_run(coordinator_task, vec![]),
    );

    for session in db::RegisteredKeys::get(&db).unwrap_or(vec![]) {
      let buf = db::SerializedKeys::get(&db, session).unwrap();
      let mut buf = buf.as_slice();

      let mut substrate_keys = vec![];
      let mut external_keys = vec![];
      while !buf.is_empty() {
        substrate_keys
          .push(ThresholdKeys::from(ThresholdCore::<Ristretto>::read(&mut buf).unwrap()));
        external_keys.push(ThresholdKeys::from(
          ThresholdCore::<CiphersuiteFor<S, Sch>>::read(&mut buf).unwrap(),
        ));
      }

      tasks.insert(
        session,
        Self::tasks(
          db.clone(),
          publisher.clone(),
          coordinator_handle.clone(),
          session,
          substrate_keys,
          external_keys,
        ),
      );
    }

    Self { db, publisher, coordinator_handle, tasks, _Sch: PhantomData, _S: PhantomData }
  }

  /// Register a set of keys to sign with.
  ///
  /// If this session (or a session after it) has already been retired, this is a NOP.
  pub fn register_keys(
    &mut self,
    txn: &mut impl DbTxn,
    session: Session,
    substrate_keys: Vec<ThresholdKeys<Ristretto>>,
    external_keys: Vec<ThresholdKeys<CiphersuiteFor<S, Sch>>>,
  ) {
    // Don't register already retired keys
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
      for (substrate_keys, external_keys) in substrate_keys.iter().zip(&external_keys) {
        buf.extend(&*substrate_keys.serialize());
        buf.extend(&*external_keys.serialize());
      }
      db::SerializedKeys::set(txn, session, &buf);
    }

    // Spawn the tasks
    self.tasks.insert(
      session,
      Self::tasks(
        self.db.clone(),
        self.publisher.clone(),
        self.coordinator_handle.clone(),
        session,
        substrate_keys,
        external_keys,
      ),
    );
  }

  /// Retire the signers for a session.
  ///
  /// This MUST be called in order, for every session (even if we didn't register keys for this
  /// session). This MUST only be called after slash report publication, or after that process
  /// times out (not once the key is done with regards to the external network).
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

    // Update RegisteredKeys/SerializedKeys
    if let Some(registered) = db::RegisteredKeys::get(txn) {
      db::RegisteredKeys::set(
        txn,
        &registered.into_iter().filter(|session_i| *session_i != session).collect(),
      );
    }
    db::SerializedKeys::del(txn, session);

    // Queue the session for clean up
    let mut to_cleanup = db::ToCleanup::get(txn).unwrap_or(vec![]);
    to_cleanup.push((session, external_key.to_bytes().as_ref().to_vec()));
    db::ToCleanup::set(txn, &to_cleanup);

    // Drop the task handles, which will cause the tasks to close
    self.tasks.remove(&session);
  }

  /// Queue handling a message.
  ///
  /// This is a cheap call and able to be done inline from a higher-level loop.
  pub fn queue_message(&mut self, txn: &mut impl DbTxn, message: &CoordinatorMessage) {
    let sign_id = message.sign_id();
    let tasks = self.tasks.get(&sign_id.session);
    match sign_id.id {
      VariantSignId::Cosign(_) => {
        db::CoordinatorToCosignerMessages::send(txn, sign_id.session, message);
        if let Some(tasks) = tasks {
          tasks.cosigner.run_now();
        }
      }
      VariantSignId::Batch(_) => {
        db::CoordinatorToBatchSignerMessages::send(txn, sign_id.session, message);
        if let Some(tasks) = tasks {
          tasks.batch.run_now();
        }
      }
      VariantSignId::SlashReport(_) => {
        db::CoordinatorToSlashReportSignerMessages::send(txn, sign_id.session, message);
        if let Some(tasks) = tasks {
          tasks.slash_report.run_now();
        }
      }
      VariantSignId::Transaction(_) => {
        db::CoordinatorToTransactionSignerMessages::send(txn, sign_id.session, message);
        if let Some(tasks) = tasks {
          tasks.transaction.run_now();
        }
      }
    }
  }

  /// Cosign a block.
  ///
  /// This is a cheap call and able to be done inline from a higher-level loop.
  pub fn cosign_block(
    &mut self,
    mut txn: impl DbTxn,
    session: Session,
    block_number: u64,
    block: [u8; 32],
  ) {
    db::ToCosign::set(&mut txn, session, &(block_number, block));
    txn.commit();

    if let Some(tasks) = self.tasks.get(&session) {
      tasks.cosigner.run_now();
    }
  }

  /// Sign a slash report.
  ///
  /// This is a cheap call and able to be done inline from a higher-level loop.
  pub fn sign_slash_report(
    &mut self,
    mut txn: impl DbTxn,
    session: Session,
    slash_report: &Vec<Slash>,
  ) {
    db::SlashReport::send(&mut txn, session, slash_report);
    txn.commit();

    if let Some(tasks) = self.tasks.get(&session) {
      tasks.slash_report.run_now();
    }
  }
}
