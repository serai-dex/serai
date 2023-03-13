use std::{
  sync::{Arc, RwLock},
  collections::VecDeque,
};

use messages::{ProcessorMessage, CoordinatorMessage};

// TODO: Also include the coin block height here so we can delay handling if not synced?
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
  pub id: u64,
  pub msg: CoordinatorMessage,
}

#[async_trait::async_trait]
pub trait Coordinator {
  async fn send(&mut self, msg: ProcessorMessage);
  async fn recv(&mut self) -> Message;
  async fn ack(&mut self, msg: Message);
}

// TODO: Move this to tests
pub struct MemCoordinator(Arc<RwLock<VecDeque<Message>>>);
impl MemCoordinator {
  #[allow(clippy::new_without_default)]
  pub fn new() -> MemCoordinator {
    MemCoordinator(Arc::new(RwLock::new(VecDeque::new())))
  }
}

#[async_trait::async_trait]
impl Coordinator for MemCoordinator {
  async fn send(&mut self, _: ProcessorMessage) {
    todo!()
  }
  async fn recv(&mut self) -> Message {
    todo!()
  }
  async fn ack(&mut self, _: Message) {
    todo!()
  }
}
