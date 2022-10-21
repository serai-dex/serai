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
    panic!("should never be called")

    // Substrate may call this at some point in the future?
    // It doesn't appear to do so now, and we have the question of what to do if/when it does
    // Either we return the chain tip, which is the true leaf yet breaks the documented definition,
    // or we return the actual leaves, when those don't contribute value
    //
    // Both become risky as best_chain, which is presumably used for block building, is explicitly
    // defined as one of these leaves. If it's returning the best chain, the finalized chain tip,
    // then it's wrong. The real comment is that this API does not support the Tendermint model
    //
    // Since it appears the blockchain operations happen on the Backend's leaves, not the
    // SelectChain's, leaving this as a panic for now should be optimal
    //
    // TODO: Triple check this isn't reachable
  }

  async fn best_chain(&self) -> Result<B::Header, Error> {
    Ok(
      self
        .0
        .blockchain()
        .header(BlockId::Hash(self.0.blockchain().last_finalized().unwrap()))
        .unwrap()
        .unwrap(),
    )
  }
}
