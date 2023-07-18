use std::{
  sync::Arc,
  collections::{VecDeque, HashMap},
};

use serai_client::primitives::NetworkId;

use processor_messages::CoordinatorMessage;

use tokio::sync::RwLock;

use crate::processors::{Message, Processors};

pub mod tributary;

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
