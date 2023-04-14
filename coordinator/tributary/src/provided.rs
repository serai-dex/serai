use std::collections::VecDeque;

use crate::{TransactionKind, Transaction};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProvidedTransactions<T: Transaction> {
  pub(crate) transactions: VecDeque<T>,
}

impl<T: Transaction> Default for ProvidedTransactions<T> {
  fn default() -> Self {
    ProvidedTransactions { transactions: VecDeque::new() }
  }
}

impl<T: Transaction> ProvidedTransactions<T> {
  pub(crate) fn new() -> Self {
    ProvidedTransactions::default()
  }

  /// Provide a transaction for inclusion in a block.
  pub(crate) fn provide(&mut self, tx: T) {
    // TODO: Make an error out of this
    assert_eq!(tx.kind(), TransactionKind::Provided, "provided a non-provided transaction");
    self.transactions.push_back(tx);
  }

  /// Complete a provided transaction, no longer proposing it nor voting for its validity.
  pub(crate) fn complete(&mut self, tx: [u8; 32]) {
    assert_eq!(self.transactions.pop_front().unwrap().hash(), tx);
  }
}
