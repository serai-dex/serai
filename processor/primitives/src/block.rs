use core::fmt::Debug;

use group::{Group, GroupEncoding};

use crate::{Id, Address, ReceivedOutput};

/// A block header from an external network.
pub trait BlockHeader: Send + Sync + Sized + Clone + Debug {
  /// The type used to identify blocks.
  type Id: 'static + Id;
  /// The ID of this block.
  fn id(&self) -> Self::Id;
  /// The ID of the parent block.
  fn parent(&self) -> Self::Id;
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
  /// The type used to represent received outputs on this external network.
  type Output: ReceivedOutput<Self::Key, Self::Address>;

  /// The ID of this block.
  fn id(&self) -> <Self::Header as BlockHeader>::Id;

  /// Scan all outputs within this block to find the outputs spendable by this key.
  fn scan_for_outputs(&self, key: Self::Key) -> Vec<Self::Output>;
}
