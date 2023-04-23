use core::fmt::Debug;
use std::{
  sync::{Arc, RwLock},
  collections::VecDeque,
};

use async_trait::async_trait;

pub use tributary::P2p as TributaryP2p;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum P2pMessageKind {
  Tributary,
}

impl P2pMessageKind {
  fn to_byte(self) -> u8 {
    match self {
      P2pMessageKind::Tributary => 0,
    }
  }

  fn from_byte(byte: u8) -> Option<P2pMessageKind> {
    match byte {
      0 => Some(P2pMessageKind::Tributary),
      _ => None,
    }
  }
}

// TODO
#[async_trait]
pub trait P2p: Send + Sync + Clone + Debug + TributaryP2p {
  async fn broadcast(&self, kind: P2pMessageKind, msg: Vec<u8>);
  async fn receive(&self) -> Option<(P2pMessageKind, Vec<u8>)>;
}

#[derive(Clone, Debug)]
pub struct LocalP2p(usize, Arc<RwLock<Vec<VecDeque<Vec<u8>>>>>);

impl LocalP2p {
  pub fn new(validators: usize) -> Vec<LocalP2p> {
    let shared = Arc::new(RwLock::new(vec![VecDeque::new(); validators]));
    let mut res = vec![];
    for i in 0 .. validators {
      res.push(LocalP2p(i, shared.clone()));
    }
    res
  }
}

#[async_trait]
impl P2p for LocalP2p {
  async fn broadcast(&self, kind: P2pMessageKind, mut msg: Vec<u8>) {
    msg.insert(0, kind.to_byte());
    for (i, msg_queue) in self.1.write().unwrap().iter_mut().enumerate() {
      if i == self.0 {
        continue;
      }
      msg_queue.push_back(msg.clone());
    }
  }

  async fn receive(&self) -> Option<(P2pMessageKind, Vec<u8>)> {
    let mut msg = self.1.write().unwrap()[self.0].pop_front()?;
    if msg.is_empty() {
      log::error!("empty p2p message");
      return None;
    }
    Some((P2pMessageKind::from_byte(msg.remove(0))?, msg))
  }
}

#[async_trait]
impl TributaryP2p for LocalP2p {
  async fn broadcast(&self, msg: Vec<u8>) {
    <Self as P2p>::broadcast(self, P2pMessageKind::Tributary, msg).await
  }
}
