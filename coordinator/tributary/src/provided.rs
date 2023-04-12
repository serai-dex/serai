use std::collections::HashMap;

use crate::{TransactionKind, Transaction};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ProvidedTransactions<T: Transaction> {
  pub(crate) transactions: HashMap<[u8; 32], T>,
}

impl<T: Transaction> Default for ProvidedTransactions<T> {
  fn default() -> Self {
    ProvidedTransactions { transactions: HashMap::new() }
  }
}

impl<T: Transaction> ProvidedTransactions<T> {
  pub fn new() -> Self {
    ProvidedTransactions::default()
  }

  /// Provide a transaction for inclusion in a block.
  pub fn provide(&mut self, tx: T) {
    assert_eq!(tx.kind(), TransactionKind::Provided, "provided a non-provided transaction");
    self.transactions.insert(tx.hash(), tx);
  }

  /// Withdraw a transaction, no longer proposing it or voting for its validity.
  ///
  /// Returns true if the transaction was withdrawn and false otherwise.
  pub fn withdraw(&mut self, tx: [u8; 32]) -> bool {
    self.transactions.remove(&tx).is_some()
  }
}
