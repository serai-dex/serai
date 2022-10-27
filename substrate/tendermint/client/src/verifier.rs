use std::sync::Arc;

use async_trait::async_trait;

use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::Block;
use sp_api::TransactionFor;

use sp_consensus::{Error, CacheKeyId, Environment};
use sc_consensus::{BlockImportParams, BlockImport, Verifier};

use sc_client_api::Backend;

use sp_tendermint::TendermintApi;

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
  > Verifier<B> for TendermintImport<B, Be, C, CIDP, E, A>
where
  TransactionFor<C, B>: Send + Sync + 'static,
  Arc<C>: BlockImport<B, Transaction = TransactionFor<C, B>>,
  <Arc<C> as BlockImport<B>>::Error: Into<Error>,
  C::Api: TendermintApi<B>,
{
  async fn verify(
    &mut self,
    mut block: BlockImportParams<B, ()>,
  ) -> Result<(BlockImportParams<B, ()>, Option<Vec<(CacheKeyId, Vec<u8>)>>), String> {
    self.check(&mut block).await.map_err(|e| format!("{}", e))?;
    Ok((block, None))
  }
}
