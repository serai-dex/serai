use core::future::Future;

pub use crate::P2p;

#[derive(Clone, Debug)]
pub struct DummyP2p;

impl P2p for DummyP2p {
  fn broadcast(&self, _: [u8; 32], _: Vec<u8>) -> impl Send + Future<Output = ()> {
    async move { unimplemented!() }
  }
}
