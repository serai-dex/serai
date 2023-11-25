use std::sync::Arc;

use serai_client::primitives::NetworkId;
use processor_messages::{ProcessorMessage, CoordinatorMessage};

use message_queue::{Service, Metadata, client::MessageQueue};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
  pub id: u64,
  pub network: NetworkId,
  pub msg: ProcessorMessage,
}

#[async_trait::async_trait]
pub trait Processors: 'static + Send + Sync + Clone {
  async fn send(&self, network: NetworkId, msg: impl Send + Into<CoordinatorMessage>);
  async fn recv(&mut self, network: NetworkId) -> Message;
  async fn ack(&mut self, msg: Message);
}

#[async_trait::async_trait]
impl Processors for Arc<MessageQueue> {
  async fn send(&self, network: NetworkId, msg: impl Send + Into<CoordinatorMessage>) {
    let msg: CoordinatorMessage = msg.into();
    let metadata =
      Metadata { from: self.service, to: Service::Processor(network), intent: msg.intent() };
    let msg = borsh::to_vec(&msg).unwrap();
    self.queue(metadata, msg).await;
  }
  async fn recv(&mut self, network: NetworkId) -> Message {
    let msg = self.next(Service::Processor(network)).await;
    assert_eq!(msg.from, Service::Processor(network));

    let id = msg.id;

    // Deserialize it into a ProcessorMessage
    let msg: ProcessorMessage =
      borsh::from_slice(&msg.msg).expect("message wasn't a borsh-encoded ProcessorMessage");

    return Message { id, network, msg };
  }
  async fn ack(&mut self, msg: Message) {
    MessageQueue::ack(self, Service::Processor(msg.network), msg.id).await
  }
}
