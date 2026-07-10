use alloc::vec::Vec;

use borsh::{io, BorshSerialize, BorshDeserialize};

use crate::{
  primitives::{BlockHash, merkle::UnbalancedMerkleTree, address::SeraiAddress},
  Transaction,
};

#[cfg(feature = "substrate")]
mod substrate;
#[cfg(feature = "substrate")]
pub use substrate::*;

/// The tag for a block's hash, forming a leaf of the Merkle tree which is `builds_upon`.
pub const BLOCK_LEAF_TAG: u8 = 0;
/// The tag for branch hashes in `builds_upon`.
pub const BLOCK_BRANCH_TAG: u8 = 1;

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
  /// The proposer of the block.
  pub proposer: SeraiAddress,
  /// The UNIX time in milliseconds this block was proposed at.
  ///
  /// This is guaranteed to be greater than the time of the immediately prior block.
  pub unix_time_in_millis: u64,
  /// The commitment to the transactions within this block, including the transaction from the
  /// start of the block.
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
  pub const SIZE: usize = 8 + 32 + 32 + 8 + 32 + 32 + 32;
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
  /// Get the proposer of this block.
  pub fn proposer(&self) -> SeraiAddress {
    match self {
      Header::V1(HeaderV1 { proposer, .. }) => *proposer,
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
    BlockHash(sp_crypto_hashing::blake2_256(&borsh::to_vec(self).unwrap()))
  }
}

/// A block.
///
/// This does not guarantee consistency nor validity. The header's `transactions_root` may not
/// match the contained transactions, among other ill effects.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize)]
pub struct Block {
  /// The block's header.
  pub header: Header,
  /// The block's transactions.
  pub transactions: Vec<Transaction>,
}

impl Block {
  /// The size limit for a block.
  ///
  /// This is enforced upon deserialization but it is still possible to create an over-sized
  ///  `Block` via directly accessing the `transactions` field.
  pub const MAX_SIZE: usize = 512 * 1024;
}

impl BorshDeserialize for Block {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let mut reader =
      serai_primitives::sp_borsh::BoundedReader::<_, { Block::MAX_SIZE }>::from(reader);
    let header = Header::deserialize_reader(&mut reader)?;
    let transactions = Vec::<Transaction>::deserialize_reader(&mut reader)?;
    Ok(Block { header, transactions })
  }
}

#[test]
fn header_getters() {
  use rand_core::{RngCore as _, OsRng};

  let number = OsRng.next_u64();

  let mut builds_upon = [0; 32];
  OsRng.fill_bytes(&mut builds_upon);
  let builds_upon = UnbalancedMerkleTree { root: builds_upon };

  let mut proposer = [0; 32];
  OsRng.fill_bytes(&mut proposer);
  let proposer = SeraiAddress(proposer);

  let unix_time_in_millis = OsRng.next_u64();

  let mut transactions_commitment = [0; 32];
  OsRng.fill_bytes(&mut transactions_commitment);
  let transactions_commitment = UnbalancedMerkleTree { root: transactions_commitment };

  let mut events_commitment = [0; 32];
  OsRng.fill_bytes(&mut events_commitment);
  let events_commitment = UnbalancedMerkleTree { root: events_commitment };

  let mut consensus_commitment = [0; 32];
  OsRng.fill_bytes(&mut consensus_commitment);

  let header = Header::V1(HeaderV1 {
    number,
    builds_upon,
    proposer,
    unix_time_in_millis,
    transactions_commitment,
    events_commitment,
    consensus_commitment,
  });

  assert_eq!(header.number(), number);
  assert_eq!(header.proposer(), proposer);
  assert_eq!(header.builds_upon(), builds_upon);
  assert_eq!(header.unix_time_in_millis(), unix_time_in_millis);
  assert_eq!(header.transactions_commitment(), transactions_commitment);
  assert_eq!(header.events_commitment(), events_commitment);
}

#[test]
fn header_size() {
  assert_eq!(
    borsh::to_vec(&HeaderV1 {
      number: u64::MAX,
      builds_upon: UnbalancedMerkleTree { root: [0xff; 32] },
      proposer: SeraiAddress([0xff; 32]),
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
      builds_upon: UnbalancedMerkleTree::EMPTY,
      proposer: SeraiAddress([0; 32]),
      unix_time_in_millis: 0,
      transactions_commitment: UnbalancedMerkleTree::EMPTY,
      events_commitment: UnbalancedMerkleTree::EMPTY,
      consensus_commitment: [0; 32]
    })
    .unwrap()
    .len(),
    HeaderV1::SIZE
  );
}
