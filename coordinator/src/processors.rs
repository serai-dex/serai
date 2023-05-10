use std::{
  sync::Arc,
  collections::{VecDeque, HashMap},
};

use tokio::sync::RwLock;

use serai_client::primitives::NetworkId;

use processor_messages::{ProcessorMessage, CoordinatorMessage};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
  pub id: u64,
  pub network: NetworkId,
  pub msg: ProcessorMessage,
}

#[async_trait::async_trait]
pub trait Processors: 'static + Send + Sync + Clone {
  async fn send(&self, network: NetworkId, msg: CoordinatorMessage);
  async fn recv(&mut self) -> Message;
  async fn ack(&mut self, msg: Message);
}

// TODO: Move this to tests
#[derive(Clone)]
pub struct MemProcessors(pub Arc<RwLock<HashMap<NetworkId, VecDeque<CoordinatorMessage>>>>);
impl MemProcessors {
  #[allow(clippy::new_without_default)]
  pub fn new() -> MemProcessors {
    MemProcessors(Arc::new(RwLock::new(HashMap::new())))
  }
}

#[async_trait::async_trait]
impl Processors for MemProcessors {
  async fn send(&self, network: NetworkId, msg: CoordinatorMessage) {
    let mut processors = self.0.write().await;
    let processor = processors.entry(network).or_insert_with(VecDeque::new);
    processor.push_back(msg);
  }
  async fn recv(&mut self) -> Message {
    todo!()
  }
  async fn ack(&mut self, _: Message) {
    todo!()
  }
}
