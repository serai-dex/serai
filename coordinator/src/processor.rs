use std::{sync::Arc, collections::VecDeque};

use tokio::sync::RwLock;

use processor_messages::{ProcessorMessage, CoordinatorMessage};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
  pub id: u64,
  pub msg: ProcessorMessage,
}

#[async_trait::async_trait]
pub trait Processor: 'static + Send + Sync + Clone {
  async fn send(&mut self, msg: CoordinatorMessage);
  async fn recv(&mut self) -> Message;
  async fn ack(&mut self, msg: Message);
}

// TODO: Move this to tests
#[derive(Clone)]
pub struct MemProcessor(pub Arc<RwLock<VecDeque<CoordinatorMessage>>>);
impl MemProcessor {
  #[allow(clippy::new_without_default)]
  pub fn new() -> MemProcessor {
    MemProcessor(Arc::new(RwLock::new(VecDeque::new())))
  }
}

#[async_trait::async_trait]
impl Processor for MemProcessor {
  async fn send(&mut self, msg: CoordinatorMessage) {
    self.0.write().await.push_back(msg)
  }
  async fn recv(&mut self) -> Message {
    todo!()
  }
  async fn ack(&mut self, _: Message) {
    todo!()
  }
}
