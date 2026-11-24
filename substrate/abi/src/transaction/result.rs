use borsh::{BorshSerialize, BorshDeserialize};

/// An error from executing a transaction's calls.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum TransactionError {
  /// A call was made with an origin not permitted to make it.
  BadOrigin,
  /// A module reported an error.
  Module {
    /// The index of the module within the runtime.
    index: u8,
    /// The error, as encoded by the module.
    error: [u8; 4],
  },
  /// Any other error.
  Other,
}

/// The result of executing a transaction.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum TransactionResult {
  /// The transaction's calls were successfully executed.
  Success,
  /// The transaction's calls failed to execute.
  ///
  /// All effects of the calls were reverted, yet the transaction's fee was still paid.
  Failure {
    /// The error which caused the failure.
    error: TransactionError,
  },
}

/// The status of a submitted transaction.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum TransactionStatus {
  /// The transaction is in the pool's future queue.
  Future,
  /// The transaction is in the pool's ready queue.
  InPool,
  /// The transaction is not in the pool and is not present in the queried block.
  Dropped,
  /// The transaction was executed with the given result.
  Executed(TransactionResult),
}
