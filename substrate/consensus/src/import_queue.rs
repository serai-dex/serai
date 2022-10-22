use std::{
  pin::Pin,
  sync::{Arc, RwLock},
  task::{Poll, /* Wake, Waker, */ Context},
  future::Future,
  time::SystemTime,
};

use sp_inherents::CreateInherentDataProviders;
use sp_runtime::traits::{Header, Block};
use sp_blockchain::HeaderBackend;
use sp_api::{BlockId, TransactionFor, ProvideRuntimeApi};

use sp_consensus::{Error, Environment};
use sc_consensus::{BlockImport, BlockImportStatus, BlockImportError, Link, BasicQueue};

use sc_service::ImportQueue;
use sc_client_api::{Backend, Finalizer};

use substrate_prometheus_endpoint::Registry;

use tendermint_machine::{ext::BlockNumber, TendermintMachine};

use crate::tendermint::TendermintImport;

pub type TendermintImportQueue<Block, Transaction> = BasicQueue<Block, Transaction>;

// Custom helpers for ImportQueue in order to obtain the result of a block's importing
struct ValidateLink<B: Block>(Option<(B::Hash, bool)>);
impl<B: Block> Link<B> for ValidateLink<B> {
  fn blocks_processed(
    &mut self,
    imported: usize,
    count: usize,
    results: Vec<(
      Result<BlockImportStatus<<B::Header as Header>::Number>, BlockImportError>,
      B::Hash,
    )>,
  ) {
    assert_eq!(imported, 1);
    assert_eq!(count, 1);
    self.0 = Some((results[0].1, results[0].0.is_ok()));
  }
}

pub(crate) struct ImportFuture<'a, B: Block, T: Send>(
  B::Hash,
  RwLock<&'a mut TendermintImportQueue<B, T>>,
);
impl<'a, B: Block, T: Send> ImportFuture<'a, B, T> {
  pub(crate) fn new(
    hash: B::Hash,
    queue: &'a mut TendermintImportQueue<B, T>,
  ) -> ImportFuture<B, T> {
    ImportFuture(hash, RwLock::new(queue))
  }
}

impl<'a, B: Block, T: Send> Future for ImportFuture<'a, B, T> {
  type Output = bool;

  fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
    let mut link = ValidateLink(None);
    self.1.write().unwrap().poll_actions(ctx, &mut link);
    if let Some(res) = link.0 {
      assert_eq!(res.0, self.0);
      Poll::Ready(res.1)
    } else {
      Poll::Pending
    }
  }
}

pub fn import_queue<
  B: Block,
  Be: Backend<B> + 'static,
  C: Send + Sync + HeaderBackend<B> + Finalizer<B, Be> + ProvideRuntimeApi<B> + 'static,
  I: Send + Sync + BlockImport<B, Transaction = TransactionFor<C, B>> + 'static,
  CIDP: CreateInherentDataProviders<B, ()> + 'static,
  E: Send + Sync + Environment<B> + 'static,
>(
  client: Arc<C>,
  inner: I,
  providers: Arc<CIDP>,
  env: E,
  spawner: &impl sp_core::traits::SpawnEssentialNamed,
  registry: Option<&Registry>,
) -> (impl Future<Output = ()>, TendermintImportQueue<B, TransactionFor<C, B>>)
where
  I::Error: Into<Error>,
  TransactionFor<C, B>: Send + Sync + 'static,
{
  let import = TendermintImport::new(client, inner, providers, env);

  let authority = {
    let machine_clone = import.machine.clone();
    let mut import_clone = import.clone();
    async move {
      *machine_clone.write().unwrap() = Some(TendermintMachine::new(
        import_clone.clone(),
        // TODO
        0,
        (BlockNumber(1), SystemTime::now()),
        import_clone
          .get_proposal(&import_clone.client.header(BlockId::Number(0u8.into())).unwrap().unwrap())
          .await,
      ));
    }
  };

  let boxed = Box::new(import.clone());
  // Use None for the justification importer since justifications always come with blocks
  // Therefore, they're never imported after the fact, mandating a importer
  let queue = || BasicQueue::new(import.clone(), boxed.clone(), None, spawner, registry);

  *futures::executor::block_on(import.queue.write()) = Some(queue());
  (authority, queue())
}
