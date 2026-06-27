use core::{future::Future, time::Duration};
use std::sync::Arc;

use zeroize::Zeroizing;
use rand_core::OsRng;
use ciphersuite::*;
use dalek_ff_group::Ristretto;

use tokio::sync::mpsc;

use serai_db::{Get, DbTxn, Db as DbTrait, create_db, db_channel};

use serai_client_serai::abi::primitives::validator_sets::ExternalValidatorSet;

use tributary_sdk::{
  TransactionKind, TransactionError, ProvidedError, TransactionTrait as _, Tributary,
};

use serai_task::{Task, TaskHandle, DoesNotError, ContinuallyRan};

use serai_env::Environment;

use message_queue::{Service, Metadata, Client as MessageQueue};

use serai_cosign::{Faulted, CosignIntent, Cosigning};
use serai_coordinator_substrate::{NewSetInformation, SignSlashReport};
use serai_coordinator_tributary::{
  Topic, Transaction, ProcessorMessages, CosignIntents, RecognizedTopics, ScanTributaryTask,
};
use serai_coordinator_p2p::P2p;

use crate::{
  Db, TributaryTransactionsFromProcessorMessages, TributaryTransactionsFromDkgConfirmation,
  RemoveParticipant, dkg_confirmation::ConfirmDkgTask,
};

create_db! {
  Coordinator {
     PublishOnRecognition: (set: ExternalValidatorSet, topic: Topic) -> Transaction,
  }
}

db_channel! {
  Coordinator {
    PendingCosigns: (set: ExternalValidatorSet) -> CosignIntent,
  }
}

/// Provide a Provided Transaction to the Tributary.
///
/// This is not a well-designed function. This is specific to the context in which its called,
/// within this file. It should only be considered an internal helper for this domain alone.
async fn provide_transaction<TD: DbTrait, P: P2p>(
  set: ExternalValidatorSet,
  tributary: &Tributary<TD, Transaction, P>,
  tx: Transaction,
) {
  match tributary.provide_transaction(tx.clone()).await {
    // The Tributary uses its own DB, so we may provide this multiple times if we reboot before
    // committing the txn which provoked this
    Ok(()) | Err(ProvidedError::AlreadyProvided) => {}
    Err(ProvidedError::NotProvided) => {
      panic!("providing a Transaction which wasn't a Provided transaction: {tx:?}");
    }
    Err(ProvidedError::InvalidProvided(e)) => {
      panic!("providing an invalid Provided transaction, tx: {tx:?}, error: {e:?}")
    }
    // The Tributary's scan task won't advance if we don't have the Provided transactions
    // present on-chain, and this enters an infinite loop to block the calling task from
    // advancing
    Err(ProvidedError::LocalMismatchesOnChain) => loop {
      serai_env::error!(
        "Tributary {set:?} was supposed to provide {tx:?} but peers disagree, halting Tributary",
      );
      // Print this every five minutes as this does need to be handled
      tokio::time::sleep(Duration::from_mins(5)).await;
    },
  }
}

/// Provides Cosign/Cosigned Transactions onto the Tributary.
pub(crate) struct ProvideCosignCosignedTransactionsTask<CD: DbTrait, TD: DbTrait, P: P2p> {
  db: CD,
  tributary_db: TD,
  set: NewSetInformation,
  tributary: Tributary<TD, Transaction, P>,
}
impl<CD: DbTrait, TD: DbTrait, P: P2p> ContinuallyRan
  for ProvideCosignCosignedTransactionsTask<CD, TD, P>
{
  type Error = String;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut made_progress = false;

      // Check if we produced any cosigns we were supposed to
      let mut pending_notable_cosign = false;
      loop {
        let mut txn = self.db.txn();

        // Fetch the next cosign this tributary should handle
        let Some(cosign) = PendingCosigns::try_recv(&mut txn, self.set.set) else { break };
        pending_notable_cosign = cosign.notable;

        // If we (Serai) haven't cosigned this block, break as this is still pending
        let latest = match Cosigning::<CD>::latest_cosigned_block_number(&txn) {
          Ok(latest) => latest,
          Err(Faulted) => {
            serai_env::error!("cosigning faulted");
            Err("cosigning faulted")?
          }
        };
        if latest < Some(cosign.block_number) {
          break;
        }

        // Because we've cosigned it, provide the TX for that
        {
          let mut txn = self.tributary_db.txn();
          CosignIntents::provide(&mut txn, self.set.set, &cosign);
          txn.commit();
        }
        provide_transaction(
          self.set.set,
          &self.tributary,
          Transaction::Cosigned { substrate_block_hash: cosign.block_hash },
        )
        .await;
        // Clear pending_notable_cosign since this cosign isn't pending
        pending_notable_cosign = false;

        // Commit the txn to clear this from PendingCosigns
        txn.commit();
        made_progress = true;
      }

      // If we don't have any notable cosigns pending, provide the next set of cosign intents
      if !pending_notable_cosign {
        let mut txn = self.db.txn();
        // intended_cosigns will only yield up to and including the next notable cosign
        for cosign in Cosigning::<CD>::intended_cosigns(&mut txn, self.set.set) {
          // Flag this cosign as pending
          PendingCosigns::send(&mut txn, self.set.set, &cosign);
          // Provide the transaction to queue it for work
          provide_transaction(
            self.set.set,
            &self.tributary,
            Transaction::Cosign { substrate_block_hash: cosign.block_hash },
          )
          .await;
        }
        txn.commit();
        made_progress = true;
      }

      Ok(made_progress)
    }
  }
}

#[must_use]
async fn add_signed_unsigned_transaction<TD: DbTrait, P: P2p>(
  tributary: &Tributary<TD, Transaction, P>,
  key: &Zeroizing<<Ristretto as WrappedGroup>::F>,
  mut tx: Transaction,
) -> bool {
  // If this is a signed transaction, sign it
  if matches!(tx.kind(), TransactionKind::Signed(_, _)) {
    tx.sign(&mut OsRng, tributary.genesis(), key);
  }

  let res = tributary.add_transaction(tx.clone()).await;
  match &res {
    // Fresh publication, already published
    Ok(true | false) => {}
    Err(
      TransactionError::TooLargeTransaction |
      TransactionError::InvalidSigner |
      TransactionError::InvalidSignature |
      TransactionError::InvalidContent,
    ) => {
      panic!("created an invalid transaction, tx: {tx:?}, err: {res:?}");
    }
    // InvalidNonce may be out-of-order TXs, not invalid ones, but we only create nonce #n+1 after
    // on-chain inclusion of the TX with nonce #n, so it is invalid within our context unless the
    // issue is this transaction was already included on-chain
    Err(TransactionError::InvalidNonce) => {
      let TransactionKind::Signed(order, signed) = tx.kind() else {
        panic!("non-Signed transaction had InvalidNonce");
      };
      let next_nonce = tributary
        .next_nonce(&signed.signer, &order)
        .await
        .expect("signer who is a present validator didn't have a nonce");
      assert_ne!(next_nonce, signed.nonce);
      // We're publishing an old transaction
      if next_nonce > signed.nonce {
        return true;
      }
      panic!("nonce in transaction wasn't contiguous with nonce on-chain");
    }
    // We've published too many transactions recently
    Err(TransactionError::TooManyInMempool) => {
      return false;
    }
    // This isn't a Provided transaction so this should never be hit
    Err(TransactionError::ProvidedAddedToMempool) => unreachable!(),
  }

  true
}

async fn add_with_recognition_check<TD: DbTrait, P: P2p>(
  set: ExternalValidatorSet,
  tributary_db: &mut TD,
  tributary: &Tributary<TD, Transaction, P>,
  key: &Zeroizing<<Ristretto as WrappedGroup>::F>,
  tx: Transaction,
) -> bool {
  let kind = tx.kind();
  match kind {
    TransactionKind::Provided(_) => provide_transaction(set, tributary, tx).await,
    TransactionKind::Unsigned | TransactionKind::Signed(_, _) => {
      // If this is a transaction with signing data, check the topic is recognized before
      // publishing
      let topic = tx.topic();
      let still_requires_recognition = if let Some(topic) = topic {
        (topic.requires_recognition() && (!RecognizedTopics::recognized(tributary_db, set, topic)))
          .then_some(topic)
      } else {
        None
      };
      if let Some(topic) = still_requires_recognition {
        // Queue the transaction until the topic is recognized
        // We use the Tributary DB for this so it's cleaned up when the Tributary DB is
        let mut tributary_txn = tributary_db.txn();
        PublishOnRecognition::set(&mut tributary_txn, set, topic, &tx);
        tributary_txn.commit();
      } else {
        // Actually add the transaction
        if !add_signed_unsigned_transaction(tributary, key, tx).await {
          return false;
        }
      }
    }
  }
  true
}

/// Adds all of the transactions sent via `TributaryTransactionsFromProcessorMessages`.
pub(crate) struct AddTributaryTransactionsTask<CD: DbTrait, TD: DbTrait, P: P2p> {
  db: CD,
  tributary_db: TD,
  tributary: Tributary<TD, Transaction, P>,
  set: NewSetInformation,
  key: Zeroizing<<Ristretto as WrappedGroup>::F>,
}
impl<CD: DbTrait, TD: DbTrait, P: P2p> ContinuallyRan for AddTributaryTransactionsTask<CD, TD, P> {
  type Error = DoesNotError;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut made_progress = false;

      // Provide/add all transactions sent our way
      loop {
        let mut txn = self.db.txn();
        let Some(tx) = TributaryTransactionsFromDkgConfirmation::try_recv(&mut txn, self.set.set)
        else {
          break;
        };

        if !add_with_recognition_check(
          self.set.set,
          &mut self.tributary_db,
          &self.tributary,
          &self.key,
          tx,
        )
        .await
        {
          break;
        }

        made_progress = true;
        txn.commit();
      }

      loop {
        let mut txn = self.db.txn();
        let Some(tx) = TributaryTransactionsFromProcessorMessages::try_recv(&mut txn, self.set.set)
        else {
          break;
        };

        if !add_with_recognition_check(
          self.set.set,
          &mut self.tributary_db,
          &self.tributary,
          &self.key,
          tx,
        )
        .await
        {
          break;
        }

        made_progress = true;
        txn.commit();
      }

      // Provide/add all transactions due to newly recognized topics
      loop {
        let mut tributary_txn = self.tributary_db.txn();
        let Some(topic) =
          RecognizedTopics::try_recv_topic_requiring_recognition(&mut tributary_txn, self.set.set)
        else {
          break;
        };
        if let Some(tx) = PublishOnRecognition::take(&mut tributary_txn, self.set.set, topic) {
          if !add_signed_unsigned_transaction(&self.tributary, &self.key, tx).await {
            break;
          }
        }

        made_progress = true;
        tributary_txn.commit();
      }

      // Publish any participant removals
      loop {
        let mut txn = self.db.txn();
        let Some(participant) = RemoveParticipant::try_recv(&mut txn, self.set.set) else { break };
        let tx = Transaction::RemoveParticipant {
          participant: self.set.participant_indexes_reverse_lookup[&participant],
          signed: Default::default(),
        };
        if !add_signed_unsigned_transaction(&self.tributary, &self.key, tx).await {
          break;
        }
        made_progress = true;
        txn.commit();
      }

      Ok(made_progress)
    }
  }
}

/// Takes the messages from ScanTributaryTask and publishes them to the message-queue.
pub(crate) struct TributaryProcessorMessagesTask<TD: DbTrait> {
  tributary_db: TD,
  set: ExternalValidatorSet,
  message_queue: Arc<MessageQueue>,
}
impl<TD: DbTrait> ContinuallyRan for TributaryProcessorMessagesTask<TD> {
  type Error = String; // TODO

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut made_progress = false;
      loop {
        let mut txn = self.tributary_db.txn();
        let Some(msg) = ProcessorMessages::try_recv(&mut txn, self.set) else { break };
        let metadata = Metadata {
          from: Service::Coordinator,
          to: Service::Processor(self.set.network),
          intent: msg.intent(),
        };
        let msg = borsh::to_vec(&msg).unwrap();
        self.message_queue.queue(metadata, msg).await?;
        txn.commit();
        made_progress = true;
      }
      Ok(made_progress)
    }
  }
}

/// Checks for the notification to sign a slash report and does so if present.
pub(crate) struct SignSlashReportTask<CD: DbTrait, TD: DbTrait, P: P2p> {
  db: CD,
  tributary_db: TD,
  tributary: Tributary<TD, Transaction, P>,
  set: NewSetInformation,
  key: Zeroizing<<Ristretto as WrappedGroup>::F>,
}
impl<CD: DbTrait, TD: DbTrait, P: P2p> ContinuallyRan for SignSlashReportTask<CD, TD, P> {
  type Error = DoesNotError;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      let mut txn = self.db.txn();
      let Some(()) = SignSlashReport::try_recv(&mut txn, self.set.set) else { return Ok(false) };

      // Fetch the slash report for this Tributary
      let mut tx =
        serai_coordinator_tributary::slash_report_transaction(&self.tributary_db, &self.set);
      tx.sign(&mut OsRng, self.tributary.genesis(), &self.key);

      let res = self.tributary.add_transaction(tx.clone()).await;
      match &res {
        // Fresh publication, already published
        Ok(true | false) => {}
        Err(
          TransactionError::TooLargeTransaction |
          TransactionError::InvalidSigner |
          TransactionError::InvalidNonce |
          TransactionError::InvalidSignature |
          TransactionError::InvalidContent,
        ) => {
          panic!("created an invalid SlashReport transaction, tx: {tx:?}, err: {res:?}");
        }
        // We've published too many transactions recently
        // Drop this txn to try to publish it again later on a future iteration
        Err(TransactionError::TooManyInMempool) => {
          drop(txn);
          return Ok(false);
        }
        // This isn't a Provided transaction so this should never be hit
        Err(TransactionError::ProvidedAddedToMempool) => unreachable!(),
      }

      txn.commit();
      Ok(true)
    }
  }
}

/// Run the scan task whenever the Tributary adds a new block.
async fn scan_on_new_block<CD: DbTrait, TD: DbTrait, P: P2p>(
  db: CD,
  set: ExternalValidatorSet,
  tributary: Tributary<TD, Transaction, P>,
  scan_tributary_task: TaskHandle,
  tasks_to_keep_alive: Vec<TaskHandle>,
) {
  loop {
    // Break once this Tributary is retired
    if crate::RetiredTributary::get(&db, set.network).map(|session| session.0) >=
      Some(set.session.0)
    {
      drop(tasks_to_keep_alive);
      break;
    }

    // Have the tributary scanner run as soon as there's a new block
    // This `expect` is unreachable since this owns the tributary object and doesn't drop it
    tributary
      .next_block_notification()
      .await
      .await
      .expect("tributary was dropped causing notification to error");
    scan_tributary_task.run_now();
  }
}

/// Spawn a Tributary.
///
/// This will:
/// - Spawn the Tributary
/// - Inform the P2P network of the Tributary
/// - Spawn the ScanTributaryTask
/// - Spawn the ProvideCosignCosignedTransactionsTask
/// - Spawn the TributaryProcessorMessagesTask
/// - Spawn the AddTributaryTransactionsTask
/// - Spawn the ConfirmDkgTask
/// - Spawn the SignSlashReportTask
/// - Iterate the scan task whenever a new block occurs (not just on the standard interval)
pub(crate) async fn spawn_tributary<P: P2p>(
  env: &Environment,
  db: Db,
  message_queue: Arc<MessageQueue>,
  p2p: P,
  p2p_add_tributary: &mpsc::UnboundedSender<(ExternalValidatorSet, Tributary<Db, Transaction, P>)>,
  set: NewSetInformation,
  serai_key: Zeroizing<<Ristretto as WrappedGroup>::F>,
) {
  // Don't spawn retired Tributaries
  if crate::db::RetiredTributary::get(&db, set.set.network).map(|session| session.0) >=
    Some(set.set.session.0)
  {
    return;
  }

  let genesis = set.tributary_genesis();

  // Since the Serai block will be finalized, then cosigned, before we handle this, this time will
  // be a couple of minutes stale. While the Tributary will still function with a start time in the
  // past, the Tributary will immediately incur round timeouts. We reduce these by adding a
  // constant delay of a couple of minutes.
  const TRIBUTARY_START_TIME_DELAY: u64 = 120;
  let start_time = set.declaration_time + TRIBUTARY_START_TIME_DELAY;

  let mut tributary_validators = Vec::with_capacity(set.validators.len());
  for (validator, weight) in set.validators.iter().copied() {
    let validator_key = <Ristretto as GroupIo>::read_G(&mut validator.0.as_slice())
      .expect("Serai validator had an invalid public key");
    let weight = u64::from(weight);
    tributary_validators.push((validator_key, weight));
  }

  // Spawn the Tributary
  let tributary_db = crate::db::tributary_db(env, set.set);
  let tributary = Tributary::new(
    tributary_db.clone(),
    genesis,
    start_time,
    serai_key.clone(),
    tributary_validators,
    p2p,
  )
  .await
  .unwrap();
  let reader = tributary.reader();

  // Inform the P2P network
  p2p_add_tributary
    .send((set.set, tributary.clone()))
    .expect("p2p's add_tributary channel was closed?");

  // Spawn the task to provide Cosign/Cosigned transactions onto the Tributary
  let (provide_cosign_cosigned_transactions_task_def, provide_cosign_cosigned_transactions_task) =
    Task::new();
  tokio::spawn(
    (ProvideCosignCosignedTransactionsTask {
      db: db.clone(),
      tributary_db: tributary_db.clone(),
      set: set.clone(),
      tributary: tributary.clone(),
    })
    .continually_run(provide_cosign_cosigned_transactions_task_def, vec![]),
  );

  // Spawn the task to send all messages from the Tributary scanner to the message-queue
  let (scan_tributary_messages_task_def, scan_tributary_messages_task) = Task::new();
  tokio::spawn(
    (TributaryProcessorMessagesTask {
      tributary_db: tributary_db.clone(),
      set: set.set,
      message_queue,
    })
    .continually_run(scan_tributary_messages_task_def, vec![]),
  );

  // Spawn the scan task
  let (scan_tributary_task_def, scan_tributary_task) = Task::new();
  tokio::spawn(
    ScanTributaryTask::<_, P>::new(tributary_db.clone(), set.clone(), reader)
      // This is the only handle for this TributaryProcessorMessagesTask, so when this task is
      // dropped, it will be too
      .continually_run(scan_tributary_task_def, vec![scan_tributary_messages_task]),
  );

  // Spawn the add transactions task
  let (add_tributary_transactions_task_def, add_tributary_transactions_task) = Task::new();
  tokio::spawn(
    (AddTributaryTransactionsTask {
      db: db.clone(),
      tributary_db: tributary_db.clone(),
      tributary: tributary.clone(),
      set: set.clone(),
      key: serai_key.clone(),
    })
    .continually_run(add_tributary_transactions_task_def, vec![]),
  );

  // Spawn the task to confirm the DKG result
  let (confirm_dkg_task_def, confirm_dkg_task) = Task::new();
  tokio::spawn(
    ConfirmDkgTask::new(db.clone(), set.clone(), tributary_db.clone(), serai_key.clone())
      .continually_run(confirm_dkg_task_def, vec![add_tributary_transactions_task]),
  );

  // Spawn the sign slash report task
  let (sign_slash_report_task_def, sign_slash_report_task) = Task::new();
  tokio::spawn(
    (SignSlashReportTask {
      db: db.clone(),
      tributary_db,
      tributary: tributary.clone(),
      set: set.clone(),
      key: serai_key,
    })
    .continually_run(sign_slash_report_task_def, vec![]),
  );

  // Whenever a new block occurs, immediately run the scan task
  // This function also preserves the ProvideCosignCosignedTransactionsTask handle until the
  // Tributary is retired, ensuring it isn't dropped prematurely and that the task don't run ad
  // infinitum
  tokio::spawn(scan_on_new_block(
    db,
    set.set,
    tributary,
    scan_tributary_task,
    vec![provide_cosign_cosigned_transactions_task, confirm_dkg_task, sign_slash_report_task],
  ));
}
