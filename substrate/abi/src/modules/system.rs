use alloc::string::String;

use borsh::{BorshSerialize, BorshDeserialize};

/// A borsh-stable, slimmed-down mirror of `sp_runtime::DispatchError`.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum DispatchError {
  /// A custom error in a module.
  Module {
    /// Module index, matching the metadata module index.
    index: u8,
    /// Module specific error value.
    error: [u8; 4],
  },
  /// Origin precondition failed.
  BadOrigin,
  /// Any other upstream-runtime `DispatchError` variant.
  Other(String),
}

/// An event from the `frame-system` pallet.
///
/// Only the events relevant to observing a submitted transaction's outcome are mirrored here.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Event {
  /// The current transaction was dispatched successfully.
  ExtrinsicSuccess,
  /// The current transaction failed to dispatch.
  ExtrinsicFailed {
    /// The reason the dispatch failed.
    error: DispatchError,
  },
}

/// The status of a transaction, as resolved by the `blockchain/transaction_status` endpoint.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum TransactionStatus {
  /// The transaction is in the pool's future queue.
  Future,
  /// The transaction is in the pool's ready queue.
  InPool,
  /// The transaction is not in the pool and is not present in the queried block.
  Dropped,
  /// The transaction was executed at the given index of the queried block, with the given
  /// dispatch outcome.
  Executed(Event),
}
