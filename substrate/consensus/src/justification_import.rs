use async_trait::async_trait;

use sp_inherents::CreateInherentDataProviders;
use sp_runtime::{
  traits::{Header, Block},
  Justification,
};
use sp_blockchain::HeaderBackend;
use sp_api::{TransactionFor, ProvideRuntimeApi};

use sp_consensus::{Error, Environment};
use sc_consensus::{BlockImport, JustificationImport};

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
  > JustificationImport<B> for TendermintImport<B, Be, C, I, CIDP, E>
where
  TransactionFor<C, B>: Send + Sync + 'static,
{
  type Error = Error;

  async fn on_start(&mut self) -> Vec<(B::Hash, <B::Header as Header>::Number)> {
    vec![]
  }

  async fn import_justification(
    &mut self,
    hash: B::Hash,
    number: <B::Header as Header>::Number,
    justification: Justification,
  ) -> Result<(), Error> {
    self.import_justification_actual(number, hash, justification)
  }
}
