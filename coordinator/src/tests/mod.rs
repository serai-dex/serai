use core::fmt::Debug;
use std::{
  sync::Arc,
  collections::{VecDeque, HashSet, HashMap},
};

use serai_client::primitives::NetworkId;

use processor_messages::CoordinatorMessage;

use async_trait::async_trait;

use tokio::sync::RwLock;

use crate::{
  processors::{Message, Processors},
  TributaryP2p, P2pMessageKind, P2p,
};

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
  async fn send(&self, network: NetworkId, msg: impl Send + Into<CoordinatorMessage>) {
    let mut processors = self.0.write().await;
    let processor = processors.entry(network).or_insert_with(VecDeque::new);
    processor.push_back(msg.into());
  }
  async fn recv(&self, _: NetworkId) -> Message {
    todo!()
  }
  async fn ack(&self, _: Message) {
    todo!()
  }
}

#[allow(clippy::type_complexity)]
#[derive(Clone, Debug)]
pub struct LocalP2p(usize, pub Arc<RwLock<(HashSet<Vec<u8>>, Vec<VecDeque<(usize, Vec<u8>)>>)>>);

impl LocalP2p {
  pub fn new(validators: usize) -> Vec<LocalP2p> {
    let shared = Arc::new(RwLock::new((HashSet::new(), vec![VecDeque::new(); validators])));
    let mut res = vec![];
    for i in 0 .. validators {
      res.push(LocalP2p(i, shared.clone()));
    }
    res
  }
}

#[async_trait]
impl P2p for LocalP2p {
  type Id = usize;

  async fn subscribe(&self, _genesis: [u8; 32]) {}
  async fn unsubscribe(&self, _genesis: [u8; 32]) {}

  async fn send_raw(&self, to: Self::Id, _genesis: Option<[u8; 32]>, msg: Vec<u8>) {
    self.1.write().await.1[to].push_back((self.0, msg));
  }

  async fn broadcast_raw(&self, _genesis: Option<[u8; 32]>, msg: Vec<u8>) {
    // Content-based deduplication
    let mut lock = self.1.write().await;
    {
      let already_sent = &mut lock.0;
      if already_sent.contains(&msg) {
        return;
      }
      already_sent.insert(msg.clone());
    }
    let queues = &mut lock.1;

    for (i, msg_queue) in queues.iter_mut().enumerate() {
      if i == self.0 {
        continue;
      }
      msg_queue.push_back((self.0, msg.clone()));
    }
  }

  async fn receive_raw(&self) -> (Self::Id, Vec<u8>) {
    // This is a cursed way to implement an async read from a Vec
    loop {
      if let Some(res) = self.1.write().await.1[self.0].pop_front() {
        return res;
      }
      tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
  }
}

#[async_trait]
impl TributaryP2p for LocalP2p {
  async fn broadcast(&self, genesis: [u8; 32], msg: Vec<u8>) {
    <Self as P2p>::broadcast(self, P2pMessageKind::Tributary(genesis), msg).await
  }
}
