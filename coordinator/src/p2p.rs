use core::fmt::Debug;
use std::{sync::Arc, io::Read, collections::VecDeque};

use async_trait::async_trait;

use tokio::sync::RwLock;

pub use tributary::P2p as TributaryP2p;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum P2pMessageKind {
  Tributary([u8; 32]),
  Heartbeat([u8; 32]),
  Block([u8; 32]),
}

impl P2pMessageKind {
  fn serialize(&self) -> Vec<u8> {
    match self {
      P2pMessageKind::Tributary(genesis) => {
        let mut res = vec![0];
        res.extend(genesis);
        res
      }
      P2pMessageKind::Heartbeat(genesis) => {
        let mut res = vec![1];
        res.extend(genesis);
        res
      }
      P2pMessageKind::Block(genesis) => {
        let mut res = vec![2];
        res.extend(genesis);
        res
      }
    }
  }

  fn read<R: Read>(reader: &mut R) -> Option<P2pMessageKind> {
    let mut kind = [0; 1];
    reader.read_exact(&mut kind).ok()?;
    match kind[0] {
      0 => Some({
        let mut genesis = [0; 32];
        reader.read_exact(&mut genesis).ok()?;
        P2pMessageKind::Tributary(genesis)
      }),
      1 => Some({
        let mut genesis = [0; 32];
        reader.read_exact(&mut genesis).ok()?;
        P2pMessageKind::Heartbeat(genesis)
      }),
      2 => Some({
        let mut genesis = [0; 32];
        reader.read_exact(&mut genesis).ok()?;
        P2pMessageKind::Block(genesis)
      }),
      _ => None,
    }
  }
}

#[derive(Clone, Debug)]
pub struct Message<P: P2p> {
  pub sender: P::Id,
  pub kind: P2pMessageKind,
  pub msg: Vec<u8>,
}

#[async_trait]
pub trait P2p: Send + Sync + Clone + Debug + TributaryP2p {
  type Id: Send + Sync + Clone + Copy + Debug;

  async fn send_raw(&self, to: Self::Id, msg: Vec<u8>);
  async fn broadcast_raw(&self, msg: Vec<u8>);
  async fn receive_raw(&self) -> (Self::Id, Vec<u8>);

  async fn send(&self, to: Self::Id, kind: P2pMessageKind, msg: Vec<u8>) {
    let mut actual_msg = kind.serialize();
    actual_msg.extend(msg);
    self.send_raw(to, actual_msg).await;
  }
  async fn broadcast(&self, kind: P2pMessageKind, msg: Vec<u8>) {
    let mut actual_msg = kind.serialize();
    actual_msg.extend(msg);
    self.broadcast_raw(actual_msg).await;
  }
  async fn receive(&self) -> Message<Self> {
    let (sender, kind, msg) = loop {
      let (sender, msg) = self.receive_raw().await;
      if msg.is_empty() {
        log::error!("empty p2p message from {sender:?}");
        continue;
      }

      let mut msg_ref = msg.as_ref();
      let Some(kind) = P2pMessageKind::read::<&[u8]>(&mut msg_ref) else {
        log::error!("invalid p2p message kind from {sender:?}");
        continue;
      };
      break (sender, kind, msg_ref.to_vec());
    };
    Message { sender, kind, msg }
  }
}

// TODO: Move this to tests
#[allow(clippy::type_complexity)]
#[derive(Clone, Debug)]
pub struct LocalP2p(usize, pub Arc<RwLock<Vec<VecDeque<(usize, Vec<u8>)>>>>);

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
  type Id = usize;

  async fn send_raw(&self, to: Self::Id, msg: Vec<u8>) {
    self.1.write().await[to].push_back((self.0, msg));
  }

  async fn broadcast_raw(&self, msg: Vec<u8>) {
    for (i, msg_queue) in self.1.write().await.iter_mut().enumerate() {
      if i == self.0 {
        continue;
      }
      msg_queue.push_back((self.0, msg.clone()));
    }
  }

  async fn receive_raw(&self) -> (Self::Id, Vec<u8>) {
    // This is a cursed way to implement an async read from a Vec
    loop {
      if let Some(res) = self.1.write().await[self.0].pop_front() {
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
