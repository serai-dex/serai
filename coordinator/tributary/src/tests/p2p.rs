pub use crate::P2p;

#[derive(Clone, Debug)]
pub struct DummyP2p;

#[async_trait::async_trait]
impl P2p for DummyP2p {
  async fn broadcast(&self, _: [u8; 32], _: Vec<u8>) {
    unimplemented!()
  }
}
