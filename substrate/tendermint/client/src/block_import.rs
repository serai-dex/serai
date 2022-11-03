use std::{marker::PhantomData, sync::Arc, collections::HashMap};

use async_trait::async_trait;

use sp_api::BlockId;
use sp_runtime::traits::Block;
use sp_blockchain::{BlockStatus, HeaderBackend, Backend as BlockchainBackend};
use sp_consensus::{Error, CacheKeyId, SelectChain};

use sc_consensus::{BlockCheckParams, BlockImportParams, ImportResult, BlockImport, Verifier};

use sc_client_api::Backend;

use crate::{TendermintValidator, tendermint::TendermintImport};

#[async_trait]
impl<T: TendermintValidator> BlockImport<T::Block> for TendermintImport<T>
where
  Arc<T::Client>: BlockImport<T::Block, Transaction = T::BackendTransaction>,
  <Arc<T::Client> as BlockImport<T::Block>>::Error: Into<Error>,
{
  type Error = Error;
  type Transaction = T::BackendTransaction;

  // TODO: Is there a DoS where you send a block without justifications, causing it to error,
  // yet adding it to the blacklist in the process preventing further syncing?
  async fn check_block(
    &mut self,
    mut block: BlockCheckParams<T::Block>,
  ) -> Result<ImportResult, Self::Error> {
    if self.client.status(BlockId::Hash(block.hash)).unwrap() == BlockStatus::InChain {
      return Ok(ImportResult::AlreadyInChain);
    }
    self.verify_order(block.parent_hash, block.number)?;

    // Does not verify origin here as origin only applies to unfinalized blocks
    // We don't have context on if this block has justifications or not

    block.allow_missing_state = false;
    block.allow_missing_parent = false;

    self.client.check_block(block).await.map_err(Into::into)
  }

  async fn import_block(
    &mut self,
    mut block: BlockImportParams<T::Block, Self::Transaction>,
    new_cache: HashMap<CacheKeyId, Vec<u8>>,
  ) -> Result<ImportResult, Self::Error> {
    if self.client.status(BlockId::Hash(block.hash)).unwrap() == BlockStatus::InChain {
      return Ok(ImportResult::AlreadyInChain);
    }
    self.check(&mut block).await?;
    self.client.import_block(block, new_cache).await.map_err(Into::into)

    // TODO: If we're a validator who just successfully synced a block, recreate the tendermint
    // machine with the new height
  }
}

#[async_trait]
impl<T: TendermintValidator> Verifier<T::Block> for TendermintImport<T>
where
  Arc<T::Client>: BlockImport<T::Block, Transaction = T::BackendTransaction>,
  <Arc<T::Client> as BlockImport<T::Block>>::Error: Into<Error>,
{
  async fn verify(
    &mut self,
    mut block: BlockImportParams<T::Block, ()>,
  ) -> Result<(BlockImportParams<T::Block, ()>, Option<Vec<(CacheKeyId, Vec<u8>)>>), String> {
    self.check(&mut block).await.map_err(|e| format!("{}", e))?;
    Ok((block, None))
  }
}

/// Tendermint's Select Chain, where the best chain is defined as the most recently finalized
/// block.
///
/// leaves panics on call due to not being applicable under Tendermint. Any provided answer would
/// have conflicts best left unraised.
//
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
