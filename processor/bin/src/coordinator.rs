use std::sync::Arc;

use tokio::sync::mpsc;

use scale::Encode;
use serai_client::{
  primitives::{NetworkId, Signature},
  validator_sets::primitives::Session,
  in_instructions::primitives::{Batch, SignedBatch},
};

use serai_env as env;
use serai_db::{Get, DbTxn, Db, create_db, db_channel};
use message_queue::{Service, Metadata, client::MessageQueue};

create_db! {
  ProcessorBinCoordinator {
    SavedMessages: () -> u64,
  }
}

db_channel! {
  ProcessorBinCoordinator {
    CoordinatorMessages: () -> Vec<u8>
  }
}

async fn send(service: Service, queue: &MessageQueue, msg: messages::ProcessorMessage) {
  let metadata = Metadata { from: service, to: Service::Coordinator, intent: msg.intent() };
  let msg = borsh::to_vec(&msg).unwrap();
  queue.queue(metadata, msg).await;
}

pub(crate) struct Coordinator {
  new_message: mpsc::UnboundedReceiver<()>,
  service: Service,
  message_queue: Arc<MessageQueue>,
}

pub(crate) struct CoordinatorSend(Service, Arc<MessageQueue>);

impl Coordinator {
  pub(crate) fn new(mut db: crate::Db) -> Self {
    let (new_message_send, new_message_recv) = mpsc::unbounded_channel();

    let network_id = match env::var("NETWORK").expect("network wasn't specified").as_str() {
      "bitcoin" => NetworkId::Bitcoin,
      "ethereum" => NetworkId::Ethereum,
      "monero" => NetworkId::Monero,
      _ => panic!("unrecognized network"),
    };
    let service = Service::Processor(network_id);
    let message_queue = Arc::new(MessageQueue::from_env(service));

    // Spawn a task to move messages from the message-queue to our database so we can achieve
    // atomicity. This is the only place we read/ack messages from
    tokio::spawn({
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
            CoordinatorMessages::send(&mut txn, &msg.msg);
            SavedMessages::set(&mut txn, &msg.id);
            txn.commit();
          }
          // Acknowledge this message
          message_queue.ack(Service::Coordinator, msg.id).await;

          // Fire that there's a new message
          new_message_send.send(()).expect("failed to tell the Coordinator there's a new message");
        }
      }
    });

    Coordinator { new_message: new_message_recv, service, message_queue }
  }

  pub(crate) fn coordinator_send(&self) -> CoordinatorSend {
    CoordinatorSend(self.service, self.message_queue.clone())
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
      match CoordinatorMessages::try_recv(txn) {
        Some(msg) => {
          return borsh::from_slice(&msg)
            .expect("message wasn't a borsh-encoded CoordinatorMessage")
        }
        None => {
          let _ =
            tokio::time::timeout(core::time::Duration::from_secs(60), self.new_message.recv())
              .await;
        }
      }
    }
  }

  #[allow(clippy::unused_async)]
  pub(crate) async fn send_message(&mut self, msg: messages::ProcessorMessage) {
    send(self.service, &self.message_queue, msg).await
  }
}

#[async_trait::async_trait]
impl signers::Coordinator for CoordinatorSend {
  type EphemeralError = ();

  async fn send(
    &mut self,
    msg: messages::sign::ProcessorMessage,
  ) -> Result<(), Self::EphemeralError> {
    // TODO: Use a fallible send for these methods
    send(self.0, &self.1, messages::ProcessorMessage::Sign(msg)).await;
    Ok(())
  }

  async fn publish_cosign(
    &mut self,
    block_number: u64,
    block: [u8; 32],
    signature: Signature,
  ) -> Result<(), Self::EphemeralError> {
    send(
      self.0,
      &self.1,
      messages::ProcessorMessage::Coordinator(
        messages::coordinator::ProcessorMessage::CosignedBlock {
          block_number,
          block,
          signature: signature.encode(),
        },
      ),
    )
    .await;
    Ok(())
  }

  async fn publish_batch(&mut self, batch: Batch) -> Result<(), Self::EphemeralError> {
    send(
      self.0,
      &self.1,
      messages::ProcessorMessage::Substrate(messages::substrate::ProcessorMessage::Batch { batch }),
    )
    .await;
    Ok(())
  }

  async fn publish_signed_batch(&mut self, batch: SignedBatch) -> Result<(), Self::EphemeralError> {
    send(
      self.0,
      &self.1,
      messages::ProcessorMessage::Coordinator(
        messages::coordinator::ProcessorMessage::SignedBatch { batch },
      ),
    )
    .await;
    Ok(())
  }

  async fn publish_slash_report_signature(
    &mut self,
    session: Session,
    signature: Signature,
  ) -> Result<(), Self::EphemeralError> {
    send(
      self.0,
      &self.1,
      messages::ProcessorMessage::Coordinator(
        messages::coordinator::ProcessorMessage::SignedSlashReport {
          session,
          signature: signature.encode(),
        },
      ),
    )
    .await;
    Ok(())
  }
}
