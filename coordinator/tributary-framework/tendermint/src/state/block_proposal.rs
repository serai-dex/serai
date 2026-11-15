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
  /// It MAY be polled multiple times, even after returning `Poll::Ready`. On all future calls to
  /// `poll`, it will return the result again. Additionally, a boolean of if the proposal has
  /// already been validated is returned.
  #[project = BlockProposalProjection]
  #[project_replace = BlockProposalReplaced]
  pub(super) enum BlockProposal<B, BP> {
    Pending {
      #[pin]
      future: BP,
    },
    Unvalidated {
      proposal: B,
    },
    Validated {
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

impl<B, BP: Future<Output = B>> BlockProposal<B, BP> {
  pub(super) fn poll<'borrow>(
    self: &'borrow mut Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<(bool, &'borrow B)> {
    if let BlockProposalProjection::Pending { future } = self.as_mut().project() {
      match future.poll(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(proposal) => self.set(BlockProposal::Unvalidated { proposal }),
      }
    }
    Poll::Ready(match self.as_mut().project() {
      BlockProposalProjection::Pending { future: _ } | BlockProposalProjection::Invalid => {
        return Poll::Pending;
      }
      BlockProposalProjection::Unvalidated { proposal } => (false, proposal),
      BlockProposalProjection::Validated { proposal } => (true, proposal),
    })
  }
}

impl<B, BP> BlockProposal<B, BP> {
  fn mark_validated(mut self: Pin<&mut Self>) {
    match self.as_mut().project_replace(BlockProposal::Invalid) {
      BlockProposalReplaced::Pending { .. } | BlockProposalReplaced::Invalid => {}
      BlockProposalReplaced::Unvalidated { proposal } |
      BlockProposalReplaced::Validated { proposal } => {
        self.set(BlockProposal::Validated { proposal });
      }
    }
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
  assert!(matches!(future.as_mut().poll(&mut context), Poll::Ready((false, &1))));
  assert!(matches!(*future, BlockProposal::Unvalidated { proposal: 1 }));
  assert!(matches!(future.as_mut().poll(&mut context), Poll::Ready((false, &1))));
  assert!(matches!(*future, BlockProposal::Unvalidated { proposal: 1 }));
  future.as_mut().mark_validated();
  assert!(matches!(*future, BlockProposal::Validated { proposal: 1 }));
  assert!(matches!(future.as_mut().poll(&mut context), Poll::Ready((true, &1))));
}

use crate::{SignatureScheme, InvalidBlock, Blockchain, Network};
use super::{BlockValidityCache, ValidateBlock, StateProjection};

pin_project_lite::pin_project! {
  #[project = OurBlockProposalProjection]
  pub(super) struct OurBlockProposal<
    'state,
    'blockchain,
    'borrow,
    B: Blockchain,
    S: Future<Output = ()>
  > {
    proposal_future: &'borrow mut Pin<&'state mut BlockProposal<B::Block, B::BlockProposal>>,
    proposer: B::Validator,
    #[pin]
    timeout: S,

    waiting_for_proposal: Option<(&'blockchain mut B, &'borrow mut BlockValidityCache<B>)>,
    #[pin]
    validate_block_future: Option<ValidateBlock<'borrow, B>>,
  }
}

impl<'state, B: Blockchain> StateProjection<'state, B> {
  #[must_use]
  pub(super) fn our_block_proposal<
    'blockchain,
    'borrow,
    N: Network<
        B::Validator,
        <B::SignatureScheme as SignatureScheme>::Signature,
        <B::SignatureScheme as SignatureScheme>::AggregateSignature,
        B::Block,
      >,
  >(
    &'borrow mut self,
    blockchain: &'blockchain mut B,
    proposer: B::Validator,
  ) -> OurBlockProposal<'state, 'blockchain, 'borrow, B, N::Sleep> {
    impl<B: Blockchain, S: Future<Output = ()>> Future for OurBlockProposal<'_, '_, '_, B, S> {
      type Output = Option<B::Block>;
      fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let OurBlockProposalProjection {
          proposal_future,
          proposer,
          timeout,

          waiting_for_proposal,
          mut validate_block_future,
        } = self.as_mut().project();

        /*
          `proposal_future` is safe to poll multiple times as it will always yield the result, if
          ready.
        */
        let mut proposal_future = proposal_future.as_mut();
        let Poll::Ready((already_validated, proposal)) = proposal_future.poll(cx) else {
          let Poll::Ready(()) = timeout.poll(cx) else { return Poll::Pending };
          // We have no proposal and therefore cannot yield a proposal message
          return Poll::Ready(None);
        };
        if already_validated {
          return Poll::Ready(Some(proposal.clone()));
        }

        // TODO: Ideally, `(waiting_for_proposal, validate_block_future)` would be an `enum`
        if validate_block_future.is_none() {
          let (blockchain, block_validity_cache) = waiting_for_proposal.take().expect(
            "`OurBlockProposal`: no `validate_block_future` after waiting for the proposal?",
          );

          /*
            Validate our proposal so we don't propose an invalid block.

            This could be a debug assertion instead, but the safety (regardless of the profile)
            of ensuring our own validator doesn't make an invalid proposal is worth the
            inefficiency.
          */
          validate_block_future
            .set(Some(block_validity_cache.validate_block(blockchain, *proposer, proposal)));
        }

        let Some(validate_block_future) = validate_block_future.as_pin_mut() else {
          panic!("no `validate_block_future` but just set to `Some` if `None`?");
        };
        let Poll::Ready(result) = validate_block_future.poll(cx) else { return Poll::Pending };

        match result {
          Ok(()) => {
            let proposal = proposal.clone();
            proposal_future.mark_validated();
            Poll::Ready(Some(proposal))
          }
          /*
            If this block is temporally invalid, don't yield it, but leave it alone to be
            potentially validated/proposed again in the future.
          */
          Err(InvalidBlock::Temporal) => Poll::Ready(None),
          /*
            If this block is fatally invalid, drop the block proposal entirely so we don't waste
            any more time trying to validate it.
          */
          Err(InvalidBlock::Fatal) => {
            proposal_future.set(BlockProposal::Invalid);
            Poll::Ready(None)
          }
        }
      }
    }

    OurBlockProposal {
      proposal_future: &mut self.proposal,
      proposer,
      timeout: N::sleep(N::BLOCK_PROCESSING_TIME),

      waiting_for_proposal: Some((blockchain, self.block_validity_cache)),
      validate_block_future: None,
    }
  }
}
