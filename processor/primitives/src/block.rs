use core::fmt::Debug;
use std::collections::HashMap;

use group::{Group, GroupEncoding};

use crate::{Id, Address, ReceivedOutput, Eventuality, EventualityTracker};

/// A block header from an external network.
pub trait BlockHeader: Send + Sync + Sized + Clone + Debug {
  /// The ID of this block.
  ///
  /// This is fixed to 32-bytes and is expected to be cryptographically binding with 128-bit
  /// security. This is not required to be the ID used natively by the external network.
  fn id(&self) -> [u8; 32];
  /// The ID of the parent block.
  fn parent(&self) -> [u8; 32];
}

/// A transaction from an external network.
pub trait Transaction: Send + Sync + Sized {
  /// The type used to identify transactions on this external network.
  type Id: Id;
}

/// A block from an external network.
///
/// A block is defined as a consensus event associated with a set of transactions. It is not
/// necessary to literally define it as whatever the external network defines as a block. For
/// external networks which finalize block(s), this block type should be a representation of all
/// transactions within a period finalization (whether block or epoch).
#[async_trait::async_trait]
pub trait Block: Send + Sync + Sized + Clone + Debug {
  /// The type used for this block's header.
  type Header: BlockHeader;

  /// The type used to represent keys on this external network.
  type Key: Group + GroupEncoding;
  /// The type used to represent addresses on this external network.
  type Address: Address;
  /// The type used to represent transactions on this external network.
  type Transaction: Transaction;
  /// The type used to represent received outputs on this external network.
  type Output: ReceivedOutput<
    Self::Key,
    Self::Address,
    TransactionId = <Self::Transaction as Transaction>::Id,
  >;
  /// The type used to represent an Eventuality for a transaction on this external network.
  type Eventuality: Eventuality<
    OutputId = <Self::Output as ReceivedOutput<Self::Key, Self::Address>>::Id,
  >;

  /// The ID of this block.
  fn id(&self) -> [u8; 32];

  /// Scan all outputs within this block to find the outputs spendable by this key.
  ///
  /// No assumption on the order of the returned outputs is made.
  fn scan_for_outputs_unordered(&self, key: Self::Key) -> Vec<Self::Output>;

  /// Check if this block resolved any Eventualities.
  ///
  /// Returns tbe resolved Eventualities, indexed by the ID of the transactions which resolved
  /// them.
  fn check_for_eventuality_resolutions(
    &self,
    eventualities: &mut EventualityTracker<Self::Eventuality>,
  ) -> HashMap<<Self::Transaction as Transaction>::Id, Self::Eventuality>;
}
