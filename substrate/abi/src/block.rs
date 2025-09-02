use alloc::vec::Vec;

use borsh::{BorshSerialize, BorshDeserialize};

use crate::{
  primitives::{BlockHash, merkle::UnbalancedMerkleTree},
  Transaction,
};

/// The tag for the hash of a transaction's event, forming a leaf of the Merkle tree of its events.
pub const TRANSACTION_EVENTS_COMMITMENT_LEAF_TAG: u8 = 0;
/// The tag for the branch hashes of transaction events.
pub const TRANSACTION_EVENTS_COMMITMENT_BRANCH_TAG: u8 = 1;
/// The tag for the hash of a transaction's hash and its events' Merkle root, forming a leaf of the
/// Merkle tree which is the events commitment.
pub const EVENTS_COMMITMENT_LEAF_TAG: u8 = 2;
/// The tag for for the branch hashes of the Merkle tree which is the events commitments.
pub const EVENTS_COMMITMENT_BRANCH_TAG: u8 = 3;

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
  /// The commitment to the transactions within this block.
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

/// A header for a block.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Header {
  /// A version 1 header.
  V1(HeaderV1),
}

impl Header {
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
/// This does not guarantee consistency. The header's `transactions_root` may not match the
/// contained transactions.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct Block {
  /// The block's header.
  pub header: Header,
  /// The block's transactions.
  pub transactions: Vec<Transaction>,
}

#[cfg(feature = "substrate")]
mod substrate {
  use core::fmt::Debug;

  use scale::{Encode, Decode, DecodeWithMemTracking, IoReader};
  use scale_info::TypeInfo;

  use sp_core::H256;
  use sp_runtime::{
    generic::{DigestItem, Digest},
    traits::{Header as HeaderTrait, HeaderProvider, Block as BlockTrait},
  };

  use super::*;

  // Add `serde` implementations which treat self as a `Vec<u8>`
  impl sp_core::serde::Serialize for Transaction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: sp_core::serde::Serializer,
    {
      <Vec<u8> as sp_core::serde::Serialize>::serialize(&self.encode(), serializer)
    }
  }
  impl<'de> sp_core::serde::Deserialize<'de> for Transaction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
      D: sp_core::serde::Deserializer<'de>,
    {
      use sp_core::serde::de::Error;
      let bytes = <Vec<u8> as sp_core::serde::Deserialize>::deserialize(deserializer)?;
      let mut reader = bytes.as_slice();
      let block = Self::decode(&mut IoReader(&mut reader)).map_err(D::Error::custom)?;
      if !reader.is_empty() {
        Err(D::Error::custom("extraneous bytes at end"))?;
      }
      Ok(block)
    }
  }

  /// The digest for all of the Serai-specific header fields added before execution of the block.
  #[derive(Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
  pub struct SeraiPreExecutionDigest {
    /// The UNIX time in milliseconds this block was created at.
    pub unix_time_in_millis: u64,
  }

  /// The digest for all of the Serai-specific header fields determined during execution of the
  /// block.
  #[derive(Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
  pub struct SeraiExecutionDigest {
    /// The commitment to the DAG this header builds upon.
    pub builds_upon: UnbalancedMerkleTree,
    /// The commitment to the transactions within this block.
    pub transactions_commitment: UnbalancedMerkleTree,
    /// The commitment to the events within this block.
    pub events_commitment: UnbalancedMerkleTree,
  }

  impl SeraiPreExecutionDigest {
    /// The consensus ID for a Serai pre-execution digest.
    pub const CONSENSUS_ID: [u8; 4] = *b"SRIP";
  }

  impl SeraiExecutionDigest {
    /// The consensus ID for a Serai execution digest.
    pub const CONSENSUS_ID: [u8; 4] = *b"SRIE";
  }

  /// The consensus data for a V1 header.
  ///
  /// This is not considered part of the protocol proper and may be pruned in the future. It's
  /// solely considered used for consensus now.
  #[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    sp_runtime::Serialize,
    sp_runtime::Deserialize,
  )]
  pub struct ConsensusV1 {
    /// The hash of the immediately preceding block.
    parent_hash: H256,
    /// The root for the Merkle tree of transactions, as defined by Substrate.
    ///
    /// The format of this differs from Serai's format for the commitment to the transactions.
    transactions_root: H256,
    /// The state root.
    state_root: H256,
    /// The consensus digests.
    digest: Digest,
  }

  /// A V1 header for a block, as needed by Substrate.
  #[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    sp_runtime::Serialize,
    sp_runtime::Deserialize,
  )]
  pub struct SubstrateHeaderV1 {
    number: u64,
    consensus: ConsensusV1,
  }

  /// A header for a block, as needed by Substrate.
  #[derive(
    Clone,
    PartialEq,
    Eq,
    Debug,
    Encode,
    Decode,
    DecodeWithMemTracking,
    TypeInfo,
    sp_runtime::Serialize,
    sp_runtime::Deserialize,
  )]
  #[allow(clippy::cast_possible_truncation)]
  pub enum SubstrateHeader {
    /// A version 1 header.
    V1(SubstrateHeaderV1),
  }

  impl From<&SubstrateHeader> for Header {
    fn from(header: &SubstrateHeader) -> Self {
      match header {
        SubstrateHeader::V1(header) => {
          let mut pre_execution_digest = None;
          let mut execution_digest = None;
          for log in header.consensus.digest.logs() {
            match log {
              DigestItem::PreRuntime(consensus, encoded)
                if *consensus == SeraiExecutionDigest::CONSENSUS_ID =>
              {
                pre_execution_digest =
                  SeraiPreExecutionDigest::deserialize_reader(&mut encoded.as_slice()).ok();
              }
              DigestItem::Consensus(consensus, encoded)
                if *consensus == SeraiExecutionDigest::CONSENSUS_ID =>
              {
                execution_digest =
                  SeraiExecutionDigest::deserialize_reader(&mut encoded.as_slice()).ok();
              }
              _ => {}
            }
          }
          Header::V1(HeaderV1 {
            number: header.number,
            builds_upon: execution_digest
              .as_ref()
              .map(|digest| digest.builds_upon)
              .unwrap_or(UnbalancedMerkleTree::EMPTY),
            unix_time_in_millis: pre_execution_digest
              .as_ref()
              .map(|digest| digest.unix_time_in_millis)
              .unwrap_or(0),
            transactions_commitment: execution_digest
              .as_ref()
              .map(|digest| digest.transactions_commitment)
              .unwrap_or(UnbalancedMerkleTree::EMPTY),
            events_commitment: execution_digest
              .as_ref()
              .map(|digest| digest.events_commitment)
              .unwrap_or(UnbalancedMerkleTree::EMPTY),
            consensus_commitment: sp_core::blake2_256(&header.consensus.encode()),
          })
        }
      }
    }
  }

  /// A block, as needed by Substrate.
  #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
  pub struct SubstrateBlock {
    header: SubstrateHeader,
    transactions: Vec<Transaction>,
  }
  impl sp_core::serde::Serialize for SubstrateBlock {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
      S: sp_core::serde::Serializer,
    {
      <Vec<u8> as sp_core::serde::Serialize>::serialize(&self.encode(), serializer)
    }
  }
  impl<'de> sp_core::serde::Deserialize<'de> for SubstrateBlock {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
      D: sp_core::serde::Deserializer<'de>,
    {
      use sp_core::serde::de::Error;
      let bytes = <Vec<u8> as sp_core::serde::Deserialize>::deserialize(deserializer)?;
      let mut reader = bytes.as_slice();
      let block = Self::decode(&mut IoReader(&mut reader)).map_err(D::Error::custom)?;
      if !reader.is_empty() {
        Err(D::Error::custom("extraneous bytes at end"))?;
      }
      Ok(block)
    }
  }

  impl HeaderTrait for SubstrateHeader {
    type Number = u64;
    type Hash = H256;
    type Hashing = sp_runtime::traits::BlakeTwo256;

    fn new(
      number: Self::Number,
      extrinsics_root: Self::Hash,
      state_root: Self::Hash,
      parent_hash: Self::Hash,
      digest: Digest,
    ) -> Self {
      SubstrateHeader::V1(SubstrateHeaderV1 {
        number,
        consensus: ConsensusV1 {
          parent_hash,
          transactions_root: extrinsics_root,
          state_root,
          digest,
        },
      })
    }

    fn number(&self) -> &Self::Number {
      match self {
        SubstrateHeader::V1(SubstrateHeaderV1 { number, .. }) => number,
      }
    }
    fn set_number(&mut self, number: Self::Number) {
      match self {
        SubstrateHeader::V1(SubstrateHeaderV1 { number: existing, .. }) => {
          *existing = number;
        }
      }
    }

    fn extrinsics_root(&self) -> &Self::Hash {
      match self {
        SubstrateHeader::V1(SubstrateHeaderV1 { consensus, .. }) => &consensus.transactions_root,
      }
    }
    fn set_extrinsics_root(&mut self, extrinsics_root: Self::Hash) {
      match self {
        SubstrateHeader::V1(SubstrateHeaderV1 { consensus, .. }) => {
          consensus.transactions_root = extrinsics_root;
        }
      }
    }

    fn state_root(&self) -> &Self::Hash {
      match self {
        SubstrateHeader::V1(SubstrateHeaderV1 { consensus, .. }) => &consensus.state_root,
      }
    }
    fn set_state_root(&mut self, state_root: Self::Hash) {
      match self {
        SubstrateHeader::V1(SubstrateHeaderV1 { consensus, .. }) => {
          consensus.state_root = state_root;
        }
      }
    }

    fn parent_hash(&self) -> &Self::Hash {
      match self {
        SubstrateHeader::V1(SubstrateHeaderV1 { consensus, .. }) => &consensus.parent_hash,
      }
    }
    fn set_parent_hash(&mut self, parent_hash: Self::Hash) {
      match self {
        SubstrateHeader::V1(SubstrateHeaderV1 { consensus, .. }) => {
          consensus.parent_hash = parent_hash;
        }
      }
    }

    fn digest(&self) -> &Digest {
      match self {
        SubstrateHeader::V1(SubstrateHeaderV1 { consensus, .. }) => &consensus.digest,
      }
    }
    fn digest_mut(&mut self) -> &mut Digest {
      match self {
        SubstrateHeader::V1(SubstrateHeaderV1 { consensus, .. }) => &mut consensus.digest,
      }
    }

    fn hash(&self) -> H256 {
      H256::from(Header::from(self).hash().0)
    }
  }

  impl HeaderProvider for SubstrateBlock {
    type HeaderT = SubstrateHeader;
  }

  impl BlockTrait for SubstrateBlock {
    type Extrinsic = Transaction;
    type Header = SubstrateHeader;
    type Hash = H256;
    fn header(&self) -> &Self::Header {
      &self.header
    }
    fn extrinsics(&self) -> &[Self::Extrinsic] {
      &self.transactions
    }
    fn deconstruct(self) -> (Self::Header, Vec<Self::Extrinsic>) {
      (self.header, self.transactions)
    }
    fn new(header: Self::Header, transactions: Vec<Self::Extrinsic>) -> Self {
      Self { header, transactions }
    }
    fn encode_from(header: &Self::Header, transactions: &[Self::Extrinsic]) -> Vec<u8> {
      let header = header.encode();
      let transactions = transactions.encode();
      let mut block = header;
      block.extend(transactions);
      block
    }
    fn hash(&self) -> Self::Hash {
      self.header.hash()
    }
  }
}
#[cfg(feature = "substrate")]
pub use substrate::*;
