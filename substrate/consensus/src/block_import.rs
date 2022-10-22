use std::collections::HashMap;

use async_trait::async_trait;

use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::Block;
use sp_blockchain::HeaderBackend;
use sp_api::{TransactionFor, ProvideRuntimeApi};

use sp_consensus::{Error, CacheKeyId, Environment};
use sc_consensus::{BlockCheckParams, BlockImportParams, ImportResult, BlockImport};

use sc_client_api::{Backend, Finalizer};

use crate::tendermint::TendermintImport;

#[async_trait]
impl<
    B: Block,
    Be: Backend<B> + 'static,
    C: Send + Sync + HeaderBackend<B> + Finalizer<B, Be> + ProvideRuntimeApi<B> + 'static,
    I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>> + 'static,
    CIDP: CreateInherentDataProviders<B, ()> + 'static,
    E: Send + Sync + Environment<B> + 'static,
  > BlockImport<B> for TendermintImport<B, Be, C, I, CIDP, E>
where
  I::Error: Into<Error>,
  TransactionFor<C, B>: Send + Sync + 'static,
{
  type Error = Error;
  type Transaction = TransactionFor<C, B>;

  // TODO: Is there a DoS where you send a block without justifications, causing it to error,
  // yet adding it to the blacklist in the process preventing further syncing?
  async fn check_block(
    &mut self,
    mut block: BlockCheckParams<B>,
  ) -> Result<ImportResult, Self::Error> {
    self.verify_order(block.parent_hash, block.number)?;

    // Does not verify origin here as origin only applies to unfinalized blocks
    // We don't have context on if this block has justifications or not

    block.allow_missing_state = false;
    block.allow_missing_parent = false;

    self.inner.write().await.check_block(block).await.map_err(Into::into)
  }

  async fn import_block(
    &mut self,
    mut block: BlockImportParams<B, TransactionFor<C, B>>,
    new_cache: HashMap<CacheKeyId, Vec<u8>>,
  ) -> Result<ImportResult, Self::Error> {
    self.check(&mut block).await?;
    self.inner.write().await.import_block(block, new_cache).await.map_err(Into::into)
  }
}
