use messages::{ProcessorMessage, CoordinatorMessage};

use message_queue::{Service, Metadata, client::MessageQueue};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
  pub id: u64,
  pub msg: CoordinatorMessage,
}

#[async_trait::async_trait]
pub trait Coordinator {
  async fn send(&mut self, msg: impl Send + Into<ProcessorMessage>);
  async fn recv(&mut self) -> Message;
  async fn ack(&mut self, msg: Message);
}

#[async_trait::async_trait]
impl Coordinator for MessageQueue {
  async fn send(&mut self, msg: impl Send + Into<ProcessorMessage>) {
    let msg: ProcessorMessage = msg.into();
    let metadata = Metadata { from: self.service, to: Service::Coordinator, intent: msg.intent() };
    let msg = borsh::to_vec(&msg).unwrap();

    self.queue(metadata, msg).await;
  }

  async fn recv(&mut self) -> Message {
    let msg = self.next(Service::Coordinator).await;

    let id = msg.id;

    // Deserialize it into a CoordinatorMessage
    let msg: CoordinatorMessage =
      borsh::from_slice(&msg.msg).expect("message wasn't a borsh-encoded CoordinatorMessage");

    return Message { id, msg };
  }

  async fn ack(&mut self, msg: Message) {
    MessageQueue::ack(self, Service::Coordinator, msg.id).await
  }
}
