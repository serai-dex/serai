use alloc::vec::Vec;

use borsh::{BorshSerialize, BorshDeserialize};

use crate::{
  primitives::{BlockHash, merkle::UnbalancedMerkleTree},
  Transaction,
};

#[cfg(feature = "substrate")]
mod substrate;
#[cfg(feature = "substrate")]
pub use substrate::*;

/// The tag for a block's header, forming a leaf of the Merkle tree which is `builds_upon`.
pub const BLOCK_HEADER_LEAF_TAG: u8 = 0;
/// The tag for branch hashes in `builds_upon`.
pub const BLOCK_HEADER_BRANCH_TAG: u8 = 1;

/// The tag for a transaction, forming a leaf of the Merkle tree which is the transactions'
/// commitment.
pub const TRANSACTION_COMMITMENT_LEAF_TAG: u8 = 2;
/// The tag for branch hashes in the transactions' commitment.
pub const TRANSACTION_COMMITMENT_BRANCH_TAG: u8 = 3;

/// The tag for the hash of a transaction's event, forming a leaf of the Merkle tree of its events.
pub const TRANSACTION_EVENTS_COMMITMENT_LEAF_TAG: u8 = 4;
/// The tag for the branch hashes of the Merkle tree for a transaction's events.
pub const TRANSACTION_EVENTS_COMMITMENT_BRANCH_TAG: u8 = 5;
/// The tag for the hash of a transaction's hash and its events' Merkle root, forming a leaf of the
/// Merkle tree which is the events' commitment.
pub const EVENTS_COMMITMENT_LEAF_TAG: u8 = 6;
/// The tag for branch hashes in the events' commitment.
pub const EVENTS_COMMITMENT_BRANCH_TAG: u8 = 7;

/// A V1 header for a block.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct HeaderV1 {
  /// The index of this block on the blockchain.
  ///
  /// The genesis block has number 0.
  pub number: u64,
  /// The commitment to the DAG this header builds upon.
  ///
  /// This is defined as an unbalanced Merkle tree so light clients may sync one header per epoch,
  /// and then may prove the inclusion of any header in logarithmic depth (without providing the
  /// entire header chain).
  ///
  /// Alternative popular options would be a Merkle Mountain Range, which makes more recent blocks
  /// cheaper to prove at the sacrifice of older blocks being more expensive to prove. An MMR isn't
  /// used in order to minimize the protocol's surface area. Additionally, even though the
  /// unbalanced Merkle tree doesn't achieve such notably short paths for recent blocks, it does
  /// inherently provide lower-depth paths to more recent items *on imbalance*.
  pub builds_upon: UnbalancedMerkleTree,
  /// The UNIX time in milliseconds this block was created at.
  pub unix_time_in_millis: u64,
  /// The commitment to the transactions within this block, including the inherent start/end of
  /// block transactions.
  pub transactions_commitment: UnbalancedMerkleTree,
  /// The commitment to the events within this block.
  ///
  /// The leaves of this tree will be of the form
  /// `(EVENTS_COMMITMENT_LEAF_TAG, transaction hash, transaction's events' Merkle tree root)`.
  /// A transaction may have the same event multiple times, yet an event may be uniquely identified
  /// by its path within the tree.
  pub events_commitment: UnbalancedMerkleTree,
  /// A commitment to the consensus data used to justify adding this block to the blockchain.
  pub consensus_commitment: [u8; 32],
}

impl HeaderV1 {
  /// The size of a serialized V1 header.
  pub const SIZE: usize = 8 + 32 + 8 + 32 + 32 + 32;
}

/// A header for a block.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Header {
  /// A version 1 header.
  V1(HeaderV1),
}

impl Header {
  /// The size of a serialized header.
  pub const SIZE: usize = 1 + HeaderV1::SIZE;

  /// Get the hash of the header.
  pub fn number(&self) -> u64 {
    match self {
      Header::V1(HeaderV1 { number, .. }) => *number,
    }
  }
  /// Get the commitment to the DAG this header builds upon.
  pub fn builds_upon(&self) -> UnbalancedMerkleTree {
    match self {
      Header::V1(HeaderV1 { builds_upon, .. }) => *builds_upon,
    }
  }
  /// Get the UNIX time, in milliseconds since the epoch, for when this block was proposed.
  pub fn unix_time_in_millis(&self) -> u64 {
    match self {
      Header::V1(HeaderV1 { unix_time_in_millis, .. }) => *unix_time_in_millis,
    }
  }
  /// The commitment to the transactions within this block.
  pub fn transactions_commitment(&self) -> UnbalancedMerkleTree {
    match self {
      Header::V1(HeaderV1 { transactions_commitment, .. }) => *transactions_commitment,
    }
  }
  /// The commitment to the events within this block.
  pub fn events_commitment(&self) -> UnbalancedMerkleTree {
    match self {
      Header::V1(HeaderV1 { events_commitment, .. }) => *events_commitment,
    }
  }
  /// Get the hash of the header.
  pub fn hash(&self) -> BlockHash {
    BlockHash(sp_core::blake2_256(&borsh::to_vec(self).unwrap()))
  }
}

/// A block.
///
/// This does not guarantee consistency nor validity. The header's `transactions_root` may not
/// match the contained transactions, among other ill effects.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct Block {
  /// The block's header.
  pub header: Header,
  /// The block's transactions.
  pub transactions: Vec<Transaction>,
}

impl Block {
  /// The size limit for a block.
  ///
  /// This is not enforced upon deserialization. The caller MUST be careful accordingly.
  pub const SIZE_LIMIT: usize = 512 * 1024;
}

#[test]
fn header_size() {
  assert_eq!(
    borsh::to_vec(&HeaderV1 {
      number: u64::MAX,
      builds_upon: UnbalancedMerkleTree { root: [0xff; 32] },
      unix_time_in_millis: u64::MAX,
      transactions_commitment: UnbalancedMerkleTree { root: [0xff; 32] },
      events_commitment: UnbalancedMerkleTree { root: [0xff; 32] },
      consensus_commitment: [0xff; 32]
    })
    .unwrap()
    .len(),
    HeaderV1::SIZE
  );

  assert_eq!(
    borsh::to_vec(&HeaderV1 {
      number: 0,
      builds_upon: UnbalancedMerkleTree { root: [0; 32] },
      unix_time_in_millis: 0,
      transactions_commitment: UnbalancedMerkleTree { root: [0; 32] },
      events_commitment: UnbalancedMerkleTree { root: [0; 32] },
      consensus_commitment: [0; 32]
    })
    .unwrap()
    .len(),
    HeaderV1::SIZE
  );
}
