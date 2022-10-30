use std::sync::Arc;

use async_trait::async_trait;

use sp_consensus::{Error, CacheKeyId};
use sc_consensus::{BlockImportParams, BlockImport, Verifier};

use crate::{types::TendermintValidator, tendermint::TendermintImport};

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
