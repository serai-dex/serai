use borsh::{BorshSerialize, BorshDeserialize};

/// An event from the system.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Event {
  /// The transaction successfully executed.
  TransactionSuccess,
  /// The transaction failed to execute.
  // TODO: Add an error to this
  TransactionFailed,
}
