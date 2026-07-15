use core::{
  pin::Pin,
  task::{Poll, Context},
  future::Future,
};

pin_project_lite::pin_project! {
  /// A block proposal which may or may not have arrived yet.
  ///
  /// This is opaque to if the block has arrived yet. One the internal future yields ready, its
  /// result will be cloned to be the result for all further polls of this future.
  #[project = BlockProposalProjection]
  pub(super) enum BlockProposal<B, BP> {
    Pending {
      #[pin]
      future: BP,
    },
    Ready {
      proposal: B,
    },
  }
}

impl<B, BP> BlockProposal<B, BP> {
  pub(super) fn new(future: BP) -> Self {
    Self::Pending { future }
  }
}

impl<B: Clone, BP: Send + Future<Output = B>> Future for BlockProposal<B, BP> {
  type Output = B;
  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    Poll::Ready(match self.as_mut().project() {
      BlockProposalProjection::Pending { future } => match future.poll(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(proposal) => {
          self.set(BlockProposal::Ready { proposal: proposal.clone() });
          proposal
        }
      },
      BlockProposalProjection::Ready { proposal } => proposal.clone(),
    })
  }
}

#[cfg(all(test, feature = "alloc"))]
#[tokio::test]
async fn block_proposal() {
  use core::{task::Waker, time::Duration};
  use alloc::boxed::Box;

  let mut context = Context::from_waker(Waker::noop());

  let duration = Duration::from_secs(1);
  let mut future = Box::pin(BlockProposal::new(async {
    tokio::time::sleep(duration).await;
    true
  }));
  assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));

  tokio::time::sleep(duration).await;

  assert!(matches!(*future, BlockProposal::Pending { future: _ }));
  assert!(matches!(future.as_mut().poll(&mut context), Poll::Ready(true)));
  assert!(matches!(*future, BlockProposal::Ready { proposal: true }));
  assert!(matches!(future.as_mut().poll(&mut context), Poll::Ready(true)));
}
