use std::{sync::Arc, collections::HashMap};

use async_trait::async_trait;

use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::Block;
use sp_api::TransactionFor;

use sp_consensus::{Error, CacheKeyId, Environment};
use sc_consensus::{BlockCheckParams, BlockImportParams, ImportResult, BlockImport};

use sc_client_api::Backend;

use crate::{
  tendermint::{TendermintClient, TendermintImport},
  Announce,
};

#[async_trait]
impl<
    B: Block,
    Be: Backend<B> + 'static,
    C: TendermintClient<B, Be>,
    CIDP: CreateInherentDataProviders<B, ()> + 'static,
    E: Send + Sync + Environment<B> + 'static,
    A: Announce<B>,
  > BlockImport<B> for TendermintImport<B, Be, C, CIDP, E, A>
where
  TransactionFor<C, B>: Send + Sync + 'static,
  Arc<C>: BlockImport<B, Transaction = TransactionFor<C, B>>,
  <Arc<C> as BlockImport<B>>::Error: Into<Error>,
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

    self.client.check_block(block).await.map_err(Into::into)
  }

  async fn import_block(
    &mut self,
    mut block: BlockImportParams<B, TransactionFor<C, B>>,
    new_cache: HashMap<CacheKeyId, Vec<u8>>,
  ) -> Result<ImportResult, Self::Error> {
    self.check(&mut block).await?;
    self.client.import_block(block, new_cache).await.map_err(Into::into)
  }
}
