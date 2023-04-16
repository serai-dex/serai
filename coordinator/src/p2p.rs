use core::fmt::Debug;

use async_trait::async_trait;

use tributary::P2p as TributaryP2p;

// TODO
#[async_trait]
pub trait P2p: Send + Sync + Clone + Debug + TributaryP2p {}

// TODO
#[derive(Clone, Debug)]
pub struct LocalP2p {}

#[async_trait]
impl TributaryP2p for LocalP2p {
  async fn broadcast(&self, msg: Vec<u8>) {
    // TODO
    todo!()
  }
}

// TODO
#[async_trait]
impl P2p for LocalP2p {}
