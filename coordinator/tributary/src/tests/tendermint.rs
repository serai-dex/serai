use tendermint::ext::Network;
use crate::{
  P2p, TendermintTx,
  tendermint::{TARGET_BLOCK_TIME, TendermintNetwork},
};

#[test]
fn assert_target_block_time() {
  use serai_db::MemDb;

  #[derive(Clone, Debug)]
  pub struct DummyP2p;

  #[async_trait::async_trait]
  impl P2p for DummyP2p {
    async fn broadcast(&self, _: [u8; 32], _: Vec<u8>) {
      unimplemented!()
    }
  }

  // Type paremeters don't matter here since we only need to call the block_time()
  // and it only relies on the constants of the trait implementation. block_time() is in seconds,
  // TARGET_BLOCK_TIME is in milliseconds.
  assert_eq!(
    <TendermintNetwork<MemDb, TendermintTx, DummyP2p> as Network>::block_time(),
    TARGET_BLOCK_TIME / 1000
  )
}
