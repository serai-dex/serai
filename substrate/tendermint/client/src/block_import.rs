use std::{marker::PhantomData, sync::Arc, collections::HashMap};

use async_trait::async_trait;

use sp_api::BlockId;
use sp_runtime::traits::{Header, Block};
use sp_blockchain::{BlockStatus, HeaderBackend, Backend as BlockchainBackend};
use sp_consensus::{Error, CacheKeyId, BlockOrigin, SelectChain};

use sc_consensus::{BlockCheckParams, BlockImportParams, ImportResult, BlockImport, Verifier};

use sc_client_api::{Backend, BlockBackend};

use crate::{TendermintValidator, tendermint::TendermintImport};

impl<T: TendermintValidator> TendermintImport<T> {
  fn check_already_in_chain(&self, hash: <T::Block as Block>::Hash) -> bool {
    let id = BlockId::Hash(hash);
    // If it's in chain, with justifications, return it's already on chain
    // If it's in chain, without justifications, continue the block import process to import its
    // justifications
    // This can be triggered if the validators add a block, without justifications, yet the p2p
    // process then broadcasts it with its justifications
    (self.client.status(id).unwrap() == BlockStatus::InChain) &&
      self.client.justifications(hash).unwrap().is_some()
  }
}

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
    if self.check_already_in_chain(block.hash) {
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
    if self.check_already_in_chain(block.header.hash()) {
      return Ok(ImportResult::AlreadyInChain);
    }

    self.check(&mut block).await?;
    self.client.import_block(block, new_cache).await.map_err(Into::into)
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
    block.origin = match block.origin {
      BlockOrigin::Genesis => BlockOrigin::Genesis,
      BlockOrigin::NetworkBroadcast => BlockOrigin::NetworkBroadcast,

      // Re-map NetworkInitialSync to NetworkBroadcast so it still triggers notifications
      // Tendermint will listen to the finality stream. If we sync a block we're running a machine
      // for, it'll force the machine to move ahead. We can only do that if there actually are
      // notifications
      //
      // Then Serai also runs data indexing code based on block addition, so ensuring it always
      // emits events ensures we always perform our necessary indexing (albeit with a race
      // condition since Substrate will eventually prune the block's state, potentially before
      // indexing finishes when syncing)
      //
      // The alternative to this would be editing Substrate directly, which would be a lot less
      // fragile, manually triggering the notifications (which may be possible with code intended
      // for testing), writing our own notification system, or implementing lock_import_and_run
      // on our end, letting us directly set the notifications, so we're not beholden to when
      // Substrate decides to call notify_finalized
      //
      // TODO: Call lock_import_and_run on our end, which already may be needed for safety reasons
      BlockOrigin::NetworkInitialSync => BlockOrigin::NetworkBroadcast,
      // Also re-map File so bootstraps also trigger notifications, enabling safely using
      // bootstraps
      BlockOrigin::File => BlockOrigin::NetworkBroadcast,

      // We do not want this block, which hasn't been confirmed, to be broadcast over the net
      // Substrate will generate notifications unless it's Genesis, which this isn't, InitialSync,
      // which changes telemetry behavior, or File, which is... close enough
      //
      // Even if we do manually implement lock_import_and_run, Substrate will still override
      // our notifications if it believes it should provide notifications. That means we *still*
      // have to keep this patch, with all its fragility, unless we edit Substrate or move the
      // the entire block import flow under Serai
      BlockOrigin::ConsensusBroadcast => BlockOrigin::File,
      BlockOrigin::Own => BlockOrigin::File,
    };

    if self.check_already_in_chain(block.header.hash()) {
      return Ok((block, None));
    }

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
