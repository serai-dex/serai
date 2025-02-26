use alloc::vec::Vec;

use borsh::{BorshSerialize, BorshDeserialize};

use crate::{primitives::BlockHash, Transaction};

/// A V1 header for a block.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct HeaderV1 {
  /// The index of this block on the blockchain.
  ///
  /// The genesis block has number 0.
  pub number: u64,
  /// The commitment to the DAG this header builds upon.
  pub builds_upon: BlockHash,
  /// The UNIX time in milliseconds this block was created at.
  pub unix_time_in_millis: u64,
  /// The commitment to the transactions within this block.
  // TODO: Some transactions don't have unique hashes due to assuming validators set unique keys
  pub transactions_commitment: [u8; 32],
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
  pub fn builds_upon(&self) -> BlockHash {
    match self {
      Header::V1(HeaderV1 { builds_upon, .. }) => *builds_upon,
    }
  }
  /// The commitment to the transactions within this block.
  pub fn transactions_commitment(&self) -> [u8; 32] {
    match self {
      Header::V1(HeaderV1 { transactions_commitment, .. }) => *transactions_commitment,
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

  use scale::{Encode, Decode};
  use scale_info::TypeInfo;

  use sp_core::H256;
  use sp_runtime::{
    generic::{DigestItem, Digest},
    traits::{Header as HeaderTrait, HeaderProvider, Block as BlockTrait},
  };

  use super::*;

  /// The digest for all of the Serai-specific header fields.
  #[derive(Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
  pub struct SeraiDigest {
    /// The commitment to the DAG this header builds upon.
    pub builds_upon: BlockHash,
    /// The UNIX time in milliseconds this block was created at.
    pub unix_time_in_millis: u64,
    /// The commitment to the transactions within this block.
    pub transactions_commitment: [u8; 32],
  }

  impl SeraiDigest {
    const CONSENSUS_ID: [u8; 4] = *b"SRID";
  }

  /// The consensus data for a V1 header.
  ///
  /// This is not considered part of the protocol proper and may be pruned in the future. It's
  /// solely considered used for consensus now.
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, sp_runtime::Serialize)]
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
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, sp_runtime::Serialize)]
  pub struct SubstrateHeaderV1 {
    number: u64,
    consensus: ConsensusV1,
  }

  /// A header for a block, as needed by Substrate.
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, sp_runtime::Serialize)]
  pub enum SubstrateHeader {
    /// A version 1 header.
    V1(SubstrateHeaderV1),
  }

  impl From<&SubstrateHeader> for Header {
    fn from(header: &SubstrateHeader) -> Self {
      match header {
        SubstrateHeader::V1(header) => {
          let digest =
            header.consensus.digest.logs().iter().find_map(|digest_item| match digest_item {
              DigestItem::PreRuntime(consensus, encoded)
                if *consensus == SeraiDigest::CONSENSUS_ID =>
              {
                SeraiDigest::deserialize_reader(&mut encoded.as_slice()).ok()
              }
              _ => None,
            });
          Header::V1(HeaderV1 {
            number: header.number,
            builds_upon: digest
              .as_ref()
              .map(|digest| digest.builds_upon)
              .unwrap_or(BlockHash::from([0; 32])),
            unix_time_in_millis: digest
              .as_ref()
              .map(|digest| digest.unix_time_in_millis)
              .unwrap_or(0),
            transactions_commitment: digest
              .as_ref()
              .map(|digest| digest.transactions_commitment)
              .unwrap_or([0; 32]),
            consensus_commitment: sp_core::blake2_256(&header.consensus.encode()),
          })
        }
      }
    }
  }

  /// A block, as needed by Substrate.
  #[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, sp_runtime::Serialize)]
  pub struct SubstrateBlock {
    header: SubstrateHeader,
    #[serde(skip)] // This makes this unsafe to deserialize, but we don't impl `Deserialize`
    transactions: Vec<Transaction>,
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
