use core::iter::Peekable;
use alloc::vec::Vec;

use crate::{
  transaction::{Signed, TransactionKind, Transaction},
  Block,
};

use super::Usize2;

struct PerSigner<T> {
  signer: Option<[u8; 32]>,
  size: usize,
  transactions: Vec<(usize, T)>,
}

impl<T: Transaction> PerSigner<T> {
  const EMPTY: Self = Self { signer: None, size: 0, transactions: alloc::vec![] };

  /// Pop a transaction from this signer.
  ///
  /// This will not affect the validity of this signer's ordering.
  fn pop(&mut self) -> Option<(usize, T)> {
    let (transaction_size, transaction) = self.transactions.pop()?;
    self.size -= transaction_size;
    Some((transaction_size, transaction))
  }

  fn iter(&self) -> impl Iterator<Item = &T> {
    self.transactions.iter().map(|(_transaction_size, transaction)| transaction)
  }

  fn collect(transactions: &mut Peekable<impl Iterator<Item = T>>) -> Option<Self> {
    let signer = |transaction: &T| match transaction.kind() {
      TransactionKind::Signed { scope: _, signed: Signed { signer, .. } } => Some(signer),
      TransactionKind::Provided { .. } | TransactionKind::Unsigned => None,
    };

    let target_signer = signer(transactions.peek()?);

    let mut result = Self { signer: target_signer, size: 0, transactions: alloc::vec![] };
    let mut full = false;

    while let Some(transaction) =
      transactions.next_if(|transaction| signer(transaction) == target_signer)
    {
      // If this signer is full, simply drain the rest of their transactions from this iterator
      if full {
        continue;
      }

      /*
        Calculate this transaction's size.

        If we can't determine this transaction's size, for whatever reason, we skip it.
        However, as it may be a required predecessor to a following transaction, we mark this
        signer as 'full'.
      */
      let Ok(transaction_size) = crate::serialized_len(&transaction) else {
        full = true;
        continue;
      };

      // Determine the new size of this signer's transactions
      let Some(new_signer_size) = result.size.checked_add(transaction_size) else {
        full = true;
        continue;
      };
      result.size = new_signer_size;
      result.transactions.push((transaction_size, transaction));
    }

    Some(result)
  }
}

pub(super) struct Transactions<T> {
  non_signed: PerSigner<T>,
  per_signer: Vec<PerSigner<T>>,
}

impl<T: Transaction> Transactions<T> {
  pub(super) const EMPTY: Self = Self { non_signed: PerSigner::EMPTY, per_signer: alloc::vec![] };

  /// Instance `Transactions` from an iterator of transactions (presumably from the mempool).
  ///
  /// This assumes the iterator is _sorted_, as necessary for these transactions to be included in
  /// a block.
  ///
  /// This function will provide a first pass to attempt to fairly trim transactions if the block's
  /// size limit would be violated. However, the result is not guaranteed to fit within the block's
  /// size limit.
  pub(super) fn from_iter(slashes_size: usize, transactions: impl IntoIterator<Item = T>) -> Self {
    let mut transactions = transactions.into_iter().peekable();

    /*
      Organize the transactions by their signer.

      This is correct by the requirement the iterator be sorted, causing each signer's transactions
      to be sequential.
    */
    let mut per_signer = alloc::vec![];
    while let Some(transactions) = PerSigner::collect(&mut transactions) {
      per_signer.push(transactions);
    }

    // Separate out the non-signed transactions
    let mut non_signed = if per_signer.first().is_some_and(|per_signer| per_signer.signer.is_none())
    {
      per_signer.remove(0)
    } else {
      PerSigner::EMPTY
    };

    let Some(capacity) = T::BLOCK_SIZE_LIMIT else {
      // If there's no block size limit, this does no further work
      return Self { non_signed, per_signer };
    };
    let Some(mut capacity) = capacity
      .checked_sub(Block::<T>::EMPTY_BLOCK_SIZE)
      .and_then(|capacity| capacity.checked_sub(slashes_size))
    else {
      // If the block's size limit is less thna an empty block's size, truncate all transactions
      return Self::EMPTY;
    };

    // If there's non-signed transactions, ensure they fit within the block's size limit
    {
      if non_signed.size > capacity {
        // If we can't fit all the non-signed transactions, we can't fit any signed transactions
        per_signer.clear();
      }
      while non_signed.size > capacity {
        let _ = non_signed.pop();
      }
      capacity -= non_signed.size;
    }

    /*
      This is guaranteed to not overflow as we're summing at most `u16::MAX` values,
      and `usize` is at least `u16`.
    */
    let signed_transactions_size = per_signer
      .iter()
      .map(|per_signer| per_signer.size)
      .fold(Usize2::ZERO, |accum, size| accum + size);

    if let Some(mut size_to_trim) = signed_transactions_size
      .checked_sub(capacity)
      .filter(|size_to_trim| *size_to_trim != Usize2::ZERO)
    {
      let target_size_per_signer = capacity / per_signer.len();

      /*
        Remove transactions until either:
        - This signer only has one transaction left
        - This signer's transactions' size are less than the amortized capacity per signer
        - All transactions are less than the block's size limit

        This does not consider the block header's size, nor the size of the slashes. This isn't
        meant to ensure the resulting block is less than the block's size limit, solely be a
        rough first pass which does _most_ of the work in a sufficiently fair manner.
      */
      'outer: for per_signer in &mut per_signer {
        while (per_signer.transactions.len() > 1) && (per_signer.size > target_size_per_signer) {
          let (transaction_size, _transaction) = per_signer.pop().unwrap();

          match size_to_trim
            .checked_sub(transaction_size)
            .filter(|size_to_trim| *size_to_trim != Usize2::ZERO)
          {
            Some(new_size_to_trim) => size_to_trim = new_size_to_trim,
            None => break 'outer,
          }
        }
      }
    }

    Self { non_signed, per_signer }
  }
}

impl<T: Transaction> Transactions<T> {
  pub(super) fn iter(&self) -> impl Iterator<Item = &T> {
    self.non_signed.iter().chain(self.per_signer.iter().flat_map(PerSigner::iter))
  }

  /// Pop a transaction.
  ///
  /// This will not affect the validity of the transactions' ordering.
  ///
  /// The value `i` is used to decide _a_ collection to remove from but it is not the index of the
  /// collection to remove from. This function will mutate `i` such that on successive calls,
  /// the collection removed from is rotated.
  pub(super) fn pop(&mut self, i: &mut u16) -> Option<(usize, T)> {
    if let Some(signer_to_remove_from) = usize::from(*i).checked_rem(self.per_signer.len()) {
      let popped = self.per_signer[signer_to_remove_from]
        .pop()
        .expect("`per_signer`'s elements are non-empty");
      if self.per_signer[signer_to_remove_from].transactions.is_empty() {
        self.per_signer.remove(signer_to_remove_from);
      } else {
        /*
          If we removed this signer's collection, this index (once reduced) will inherently point
          to the next signer's collection. It's only if we didn't remove this signer's collection
          we need to increment the index such that it points to the next signer's collection.
        */
        *i = i.wrapping_add(1);
      }
      Some(popped)
    } else {
      self.non_signed.pop()
    }
  }
}
