use core::future::Future;
use std::sync::{LazyLock, Arc, Mutex};

use tokio::sync::mpsc;

use serai_client::{
  primitives::Signature,
  validator_sets::primitives::{Session, SlashReport},
  in_instructions::primitives::SignedBatch,
};

use serai_cosign::SignedCosign;

use serai_db::{Get, DbTxn, Db, create_db, db_channel};

use scanner::ScannerFeed;

use message_queue::{Service, Metadata, client::MessageQueue};

create_db! {
  ProcessorBinCoordinator {
    SavedMessages: () -> u64,
  }
}

db_channel! {
  ProcessorBinCoordinator {
    ReceivedCoordinatorMessages: () -> Vec<u8>,
  }
}

// A lock to access SentCoordinatorMessages::send
static SEND_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

db_channel! {
  ProcessorBinCoordinator {
    SentCoordinatorMessages: () -> Vec<u8>,
  }
}

#[derive(Clone)]
pub(crate) struct CoordinatorSend {
  db: crate::Db,
  sent_message: mpsc::UnboundedSender<()>,
}

impl CoordinatorSend {
  fn send(&mut self, msg: &messages::ProcessorMessage) {
    let _lock = SEND_LOCK.lock().unwrap();
    let mut txn = self.db.txn();
    SentCoordinatorMessages::send(&mut txn, &borsh::to_vec(msg).unwrap());
    txn.commit();
    self
      .sent_message
      .send(())
      .expect("failed to tell the Coordinator tasks there's a new message to send");
  }
}

pub(crate) struct Coordinator {
  received_message: mpsc::UnboundedReceiver<()>,
  send: CoordinatorSend,
}

impl Coordinator {
  pub(crate) fn new<S: ScannerFeed>(db: crate::Db) -> Self {
    let (received_message_send, received_message_recv) = mpsc::unbounded_channel();
    let (sent_message_send, mut sent_message_recv) = mpsc::unbounded_channel();

    let service = Service::Processor(S::NETWORK);
    let message_queue = Arc::new(MessageQueue::from_env(service));

    // Spawn a task to move messages from the message-queue to our database so we can achieve
    // atomicity. This is the only place we read/ack messages from
    tokio::spawn({
      let mut db = db.clone();
      let message_queue = message_queue.clone();
      async move {
        loop {
          let msg = message_queue.next(Service::Coordinator).await;

          let prior_msg = msg.id.checked_sub(1);
          let saved_messages = SavedMessages::get(&db);
          /*
            This should either be:
              A) The message after the message we just saved (as normal)
              B) The message we just saved (if we rebooted and failed to ack it)
          */
          assert!((saved_messages == prior_msg) || (saved_messages == Some(msg.id)));
          if saved_messages < Some(msg.id) {
            let mut txn = db.txn();
            ReceivedCoordinatorMessages::send(&mut txn, &msg.msg);
            SavedMessages::set(&mut txn, &msg.id);
            txn.commit();
          }
          // Acknowledge this message
          message_queue.ack(Service::Coordinator, msg.id).await;

          // Fire that there's a new message
          // This assumes the success path, not the just-rebooted-path
          received_message_send
            .send(())
            .expect("failed to tell the Coordinator there's a new message");
        }
      }
    });

    // Spawn a task to send messages to the message-queue
    // TODO: Define a proper task for this and remove use of queue_with_retry
    tokio::spawn({
      let mut db = db.clone();
      async move {
        loop {
          let mut txn = db.txn();
          match SentCoordinatorMessages::try_recv(&mut txn) {
            Some(msg) => {
              let metadata = Metadata {
                from: service,
                to: Service::Coordinator,
                intent: borsh::from_slice::<messages::ProcessorMessage>(&msg).unwrap().intent(),
              };
              message_queue.queue_with_retry(metadata, msg).await;
              txn.commit();
            }
            None => {
              let _ =
                tokio::time::timeout(core::time::Duration::from_secs(6), sent_message_recv.recv())
                  .await;
            }
          }
        }
      }
    });

    let send = CoordinatorSend { db, sent_message: sent_message_send };
    Coordinator { received_message: received_message_recv, send }
  }

  pub(crate) fn coordinator_send(&self) -> CoordinatorSend {
    self.send.clone()
  }

  /// Fetch the next message from the Coordinator.
  ///
  /// This message is guaranteed to have never been handled before, where handling is defined as
  /// this `txn` being committed.
  pub(crate) async fn next_message(
    &mut self,
    txn: &mut impl DbTxn,
  ) -> messages::CoordinatorMessage {
    loop {
      match ReceivedCoordinatorMessages::try_recv(txn) {
        Some(msg) => {
          return borsh::from_slice(&msg)
            .expect("message wasn't a borsh-encoded CoordinatorMessage")
        }
        None => {
          let _ =
            tokio::time::timeout(core::time::Duration::from_secs(60), self.received_message.recv())
              .await;
        }
      }
    }
  }

  pub(crate) fn send_message(&mut self, msg: &messages::ProcessorMessage) {
    self.send.send(msg);
  }
}

impl signers::Coordinator for CoordinatorSend {
  type EphemeralError = ();

  fn send(
    &mut self,
    msg: messages::sign::ProcessorMessage,
  ) -> impl Send + Future<Output = Result<(), Self::EphemeralError>> {
    async move {
      self.send(&messages::ProcessorMessage::Sign(msg));
      Ok(())
    }
  }

  fn publish_cosign(
    &mut self,
    cosign: SignedCosign,
  ) -> impl Send + Future<Output = Result<(), Self::EphemeralError>> {
    async move {
      self.send(&messages::ProcessorMessage::Coordinator(
        messages::coordinator::ProcessorMessage::CosignedBlock { cosign },
      ));
      Ok(())
    }
  }

  fn publish_signed_batch(
    &mut self,
    batch: SignedBatch,
  ) -> impl Send + Future<Output = Result<(), Self::EphemeralError>> {
    async move {
      self.send(&messages::ProcessorMessage::Coordinator(
        messages::coordinator::ProcessorMessage::SignedBatch { batch },
      ));
      Ok(())
    }
  }

  fn publish_slash_report_signature(
    &mut self,
    session: Session,
    slash_report: SlashReport,
    signature: Signature,
  ) -> impl Send + Future<Output = Result<(), Self::EphemeralError>> {
    async move {
      self.send(&messages::ProcessorMessage::Coordinator(
        messages::coordinator::ProcessorMessage::SignedSlashReport {
          session,
          slash_report,
          signature: signature.0,
        },
      ));
      Ok(())
    }
  }
}
