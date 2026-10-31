use core::{
  pin::Pin,
  task::{Poll, Context},
};
use alloc::{boxed::Box, vec::Vec, collections::BTreeMap};

use tendermint::Network;

use crate::{
  ReadWriteAsBorsh,
  transaction::{Signed, TransactionKind, Transaction},
  block::{SyntacticError, Block},
  AggregateSignature,
};

use super::Slash;

mod usize2;
use usize2::Usize2;

mod minimum_block_time;
use minimum_block_time::MinimumBlockTime;

mod transactions;
use transactions::Transactions;

pin_project_lite::pin_project! {
  struct BlockProposalInner<Sleep, TransactionsFuture> {
    genesis: [u8; 32],

    parent: [u8; 32],

    #[pin]
    minimum_block_time: MinimumBlockTime<Sleep>,

    slashes: BTreeMap<[u8; 32], Slash>,
    #[pin]
    transactions: TransactionsFuture,

    // This is a weak form of entropy used to decide which validator to remove the transactions of
    // first. It doesn't have to satisfy any cryptographic requirements, it solely has to be
    // updated between blocks in order to ensure the validator removed from first isn't static.
    //
    // Only requiring weak entropy does mean this can theoretically be predicted by the adversary.
    // With the adversary selecting which validators have outstanding transactions, the adversary
    // can game which validators have their transactions removed (and therefore which have their
    // transactions remain). This is even easier since validators running this code will
    // consistently use the block number for 'entropy'. However, the practical effort of such an
    // attack is considered infeasible.
    weak_entropy: u64,
  }
}

pin_project_lite::pin_project! {
  #[project = BlockProposalProjection]
  pub(crate) enum BlockProposal<Sleep, TransactionsFuture> {
    None,
    Some {
      #[pin]
      inner: BlockProposalInner<Sleep, TransactionsFuture>
    },
  }
}

impl<Sleep, TransactionsFuture> BlockProposal<Sleep, TransactionsFuture> {
  pub(super) fn none() -> Self {
    Self::None
  }

  pub(super) fn some<
    T: Transaction,
    N: Network<[u8; 32], [u8; 64], AggregateSignature, ReadWriteAsBorsh<Block<T>>, Sleep = Sleep>,
  >(
    genesis: [u8; 32],
    parent: [u8; 32],
    minimum_block_time: u64,
    slashes: BTreeMap<[u8; 32], Slash>,
    transactions: TransactionsFuture,
    weak_entropy: u64,
  ) -> BlockProposal<Sleep, TransactionsFuture> {
    Self::Some {
      inner: BlockProposalInner {
        genesis,
        parent,
        minimum_block_time: MinimumBlockTime::new::<T, N>(minimum_block_time),
        slashes,
        transactions,
        weak_entropy,
      },
    }
  }
}

impl<
  T: Transaction,
  Sleep: Future<Output = ()>,
  TransactionsFuture: Future<Output: IntoIterator<Item = T>>,
> Future for BlockProposal<Sleep, TransactionsFuture>
{
  type Output = ReadWriteAsBorsh<Block<T>>;
  fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    let projection = match self.project() {
      BlockProposalProjection::None => return Poll::Pending,
      BlockProposalProjection::Some { inner } => inner.project(),
    };

    let Poll::Ready(block_time) = projection.minimum_block_time.poll(cx) else {
      return Poll::Pending;
    };

    // Receive the transactions from the mempool
    let Poll::Ready(transactions) = projection.transactions.poll(cx) else {
      return Poll::Pending;
    };

    // Remove transactions from signers who have pending slashes
    let transactions =
      transactions.into_iter().filter(|tx| {
        if let TransactionKind::Signed {
          scope: _,
          signed: Signed { signer, nonce: _, signature: _ },
        } = tx.kind() &&
          projection.slashes.contains_key(&signer)
        {
          return false;
        }
        true
      });

    let mut slashes = projection
      .slashes
      .values()
      .filter_map(|slash| crate::serialized_len(slash).ok().map(|slash_size| (slash_size, slash)))
      .collect::<Vec<_>>();

    let mut transactions = if let Some(slashes_size) =
      slashes.iter().map(|(slash_size, _slash)| *slash_size).try_fold(0usize, usize::checked_add)
    {
      Transactions::from_iter(slashes_size, transactions)
    } else {
      // If we cannot determine the sum size of the slashes, there's no room for any transactions
      Transactions::EMPTY
    };
    let mut transactions_pop_i =
      u16::try_from((*projection.weak_entropy) & u64::from(u16::MAX)).unwrap();

    let block = loop {
      match Block::instantiate(
        *projection.genesis,
        *projection.parent,
        block_time,
        slashes.iter().map(|(_slash_size, slash)| *slash).cloned().collect::<Box<[_]>>(),
        transactions.iter().cloned().collect::<Box<[_]>>(),
      ) {
        Ok(block) => break block,
        Err(err) => {
          // If even an empty block is syntactically invalid, don't yield a proposal
          if slashes.is_empty() && transactions.iter().next().is_none() {
            return Poll::Pending;
          }

          let mut size_to_trim = if let Some(block_size_limit) = T::BLOCK_SIZE_LIMIT &&
            let SyntacticError::ExceededSizeLimit { size: Some(size) } = err
          {
            size.checked_sub(block_size_limit)
          } else {
            None
          };

          /*
            If this block is syntactically invalid, assume the mempool provided invalid
            transactions _or_ this block is over the size limit. Either problem can be solved by
            popping transactions, except if over the size limit due to the slashes.

            This also smooths over any issues with the mempool, if it yielded invalid transactions
            or an invalid ordering.
          */
          while {
            let removed_len = transactions
              .pop(&mut transactions_pop_i)
              .map(|(transaction_size, _transaction)| transaction_size);

            /*
              If this block has no transactions, but has slashes, and is invalid, assume it's
              over the size limit and pop slashes until it's within the size limit.
            */
            let removed_len =
              removed_len.or_else(|| slashes.pop().map(|(slash_size, _slash)| slash_size));

            if let Some(removed_len) = removed_len {
              size_to_trim =
                size_to_trim.and_then(|size_to_trim| size_to_trim.checked_sub(removed_len));

              // Continue removing items while we know we should trim more
              size_to_trim.is_some_and(|size_to_trim| size_to_trim > 0)
            } else {
              // We couldn't remove anything/we couldn't determine how much we should remove
              false
            }
          } {}
        }
      }
    };

    Poll::Ready(ReadWriteAsBorsh(block))
  }
}
