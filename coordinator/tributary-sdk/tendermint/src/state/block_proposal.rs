use core::{
  pin::Pin,
  task::{Poll, Context},
  future::Future,
};

pin_project_lite::pin_project! {
  /// A block proposal which may or may not have arrived yet.
  ///
  /// This is opaque to if the block has arrived yet.
  ///
  /// Once the internal future is `Ready`, this will yield `(true, block.clone())`. All following
  /// calls will yield `(false, block.clone())`.
  #[project = BlockProposalProjection]
  pub(super) enum BlockProposal<B, BP> {
    Pending {
      #[pin]
      future: BP,
    },
    Ready {
      proposal: B,
    },
    Invalid,
  }
}

impl<B, BP> BlockProposal<B, BP> {
  pub(super) fn new(future: BP) -> Self {
    Self::Pending { future }
  }
}

impl<B: Clone, BP: Future<Output = B>> Future for BlockProposal<B, BP> {
  type Output = (bool, B);
  fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    Poll::Ready(match self.as_mut().project() {
      BlockProposalProjection::Pending { future } => match future.poll(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(proposal) => {
          self.set(BlockProposal::Ready { proposal: proposal.clone() });
          (true, proposal)
        }
      },
      BlockProposalProjection::Ready { proposal } => (false, proposal.clone()),
      BlockProposalProjection::Invalid => return Poll::Pending,
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
    1
  }));
  assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));

  tokio::time::sleep(duration).await;

  assert!(matches!(*future, BlockProposal::Pending { future: _ }));
  assert!(matches!(future.as_mut().poll(&mut context), Poll::Ready((true, 1))));
  assert!(matches!(*future, BlockProposal::Ready { proposal: 1 }));
  assert!(matches!(future.as_mut().poll(&mut context), Poll::Ready((false, 1))));
}
