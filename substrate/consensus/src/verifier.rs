use async_trait::async_trait;

use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::Block;
use sp_blockchain::HeaderBackend;
use sp_api::{TransactionFor, ProvideRuntimeApi};

use sp_consensus::{CacheKeyId, Environment};
use sc_consensus::{BlockImportParams, Verifier, BlockImport};

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
  > Verifier<B> for TendermintImport<B, Be, C, I, CIDP, E>
where
  TransactionFor<C, B>: Send + Sync + 'static,
{
  async fn verify(
    &mut self,
    mut block: BlockImportParams<B, ()>,
  ) -> Result<(BlockImportParams<B, ()>, Option<Vec<(CacheKeyId, Vec<u8>)>>), String> {
    self.check(&mut block).await.map_err(|e| format!("{}", e))?;
    Ok((block, None))
  }
}
