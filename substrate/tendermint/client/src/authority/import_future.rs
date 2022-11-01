use std::{
  pin::Pin,
  sync::RwLock,
  task::{Poll, Context},
  future::Future,
};

use sp_runtime::traits::{Header, Block};

use sp_consensus::Error;
use sc_consensus::{BlockImportStatus, BlockImportError, Link};

use sc_service::ImportQueue;

use tendermint_machine::ext::BlockError;

use crate::TendermintImportQueue;

// Custom helpers for ImportQueue in order to obtain the result of a block's importing
struct ValidateLink<B: Block>(Option<(B::Hash, Result<(), BlockError>)>);
impl<B: Block> Link<B> for ValidateLink<B> {
  fn blocks_processed(
    &mut self,
    imported: usize,
    count: usize,
    mut results: Vec<(
      Result<BlockImportStatus<<B::Header as Header>::Number>, BlockImportError>,
      B::Hash,
    )>,
  ) {
    assert_eq!(imported, 1);
    assert_eq!(count, 1);
    self.0 = Some((
      results[0].1,
      match results.swap_remove(0).0 {
        Ok(_) => Ok(()),
        Err(BlockImportError::Other(Error::Other(err))) => Err(
          err.downcast::<BlockError>().map(|boxed| *boxed.as_ref()).unwrap_or(BlockError::Fatal),
        ),
        _ => Err(BlockError::Fatal),
      },
    ));
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
  type Output = Result<(), BlockError>;

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
