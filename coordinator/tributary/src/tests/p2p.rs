// TODO: this file is a copy of coordinator/p2p.rs

use async_trait::async_trait;

pub use crate::P2p;

#[allow(clippy::type_complexity)]
#[derive(Clone, Debug)]
pub struct DummyP2p;

#[async_trait]
impl P2p for DummyP2p {
  async fn broadcast(&self, _: [u8; 32], _: Vec<u8>) {
    unimplemented!()
  }
}
