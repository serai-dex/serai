use std::{
  pin::Pin,
  sync::{Arc, RwLock},
  task::{Poll, Context},
  future::Future,
};

use sp_runtime::traits::{Header, Block};

use sp_consensus::Error;
use sc_consensus::{BlockImportStatus, BlockImportError, BlockImport, Link, BasicQueue};

use sc_service::ImportQueue;

use substrate_prometheus_endpoint::Registry;

use crate::{
  types::TendermintValidator,
  tendermint::{TendermintImport, TendermintAuthority},
};

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

pub fn import_queue<T: TendermintValidator>(
  client: Arc<T::Client>,
  announce: T::Announce,
  providers: Arc<T::CIDP>,
  env: T::Environment,
  spawner: &impl sp_core::traits::SpawnEssentialNamed,
  registry: Option<&Registry>,
) -> (TendermintAuthority<T>, TendermintImportQueue<T::Block, T::BackendTransaction>)
where
  Arc<T::Client>: BlockImport<T::Block, Transaction = T::BackendTransaction>,
  <Arc<T::Client> as BlockImport<T::Block>>::Error: Into<Error>,
{
  let import = TendermintImport::<T>::new(client, announce, providers, env);
  let authority = TendermintAuthority(import.clone());

  let boxed = Box::new(import.clone());
  // Use None for the justification importer since justifications always come with blocks
  // Therefore, they're never imported after the fact, mandating a importer
  let queue = || BasicQueue::new(import.clone(), boxed.clone(), None, spawner, registry);

  *futures::executor::block_on(import.queue.write()) = Some(queue());
  (authority, queue())
}
