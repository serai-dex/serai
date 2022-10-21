// SelectChain, while provided by Substrate and part of PartialComponents, isn't used by Substrate
// It's common between various block-production/finality crates, yet Substrate as a system doesn't
// rely on it, which is good, because its definition is explicitly incompatible with Tendermint
//
// leaves is supposed to return all leaves of the blockchain. While Tendermint maintains that view,
// an honest node will only build on the most recently finalized block, so it is a 'leaf' despite
// having descendants
//
// best_chain will always be this finalized block, yet Substrate explicitly defines it as one of
// the above leaves, which this finalized block is explicitly not included in. Accordingly, we
// can never provide a compatible decision
//
// Since PartialComponents expects it, an implementation which does its best is provided. It panics
// if leaves is called, yet returns the finalized chain tip for best_chain, as that's intended to
// be the header to build upon

use std::{marker::PhantomData, sync::Arc};

use async_trait::async_trait;

use sp_api::BlockId;
use sp_runtime::traits::Block;
use sp_blockchain::{HeaderBackend, Backend as BlockchainBackend};
use sc_client_api::Backend;
use sp_consensus::{Error, SelectChain};

pub struct TendermintSelectChain<B: Block, Be: Backend<B>>(Arc<Be>, PhantomData<B>);

impl<B: Block, Be: Backend<B>> Clone for TendermintSelectChain<B, Be> {
  fn clone(&self) -> Self {
    TendermintSelectChain(self.0.clone(), PhantomData)
  }
}

impl<B: Block, Be: Backend<B>> TendermintSelectChain<B, Be> {
  pub fn new(backend: Arc<Be>) -> TendermintSelectChain<B, Be> {
    TendermintSelectChain(backend, PhantomData)
  }
}

#[async_trait]
impl<B: Block, Be: Backend<B>> SelectChain<B> for TendermintSelectChain<B, Be> {
  async fn leaves(&self) -> Result<Vec<B::Hash>, Error> {
    panic!("Substrate definition of leaves is incompatible with Tendermint")
  }

  async fn best_chain(&self) -> Result<B::Header, Error> {
    Ok(
      self
        .0
        .blockchain()
        // There should always be a finalized block
        .header(BlockId::Hash(self.0.blockchain().last_finalized().unwrap()))
        // There should not be an error in retrieving it and since it's finalized, it should exist
        .unwrap()
        .unwrap(),
    )
  }
}
