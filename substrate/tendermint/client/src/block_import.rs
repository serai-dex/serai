use std::{sync::Arc, collections::HashMap};

use async_trait::async_trait;

use sp_consensus::{Error, CacheKeyId};
use sc_consensus::{BlockCheckParams, BlockImportParams, ImportResult, BlockImport};

use crate::{types::TendermintAuthor, tendermint::TendermintImport};

#[async_trait]
impl<T: TendermintAuthor> BlockImport<T::Block> for TendermintImport<T>
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
    self.check(&mut block).await?;
    self.client.import_block(block, new_cache).await.map_err(Into::into)

    // TODO: If we're a validator who just successfully synced a block, recreate the tendermint
    // machine with the new height
  }
}
