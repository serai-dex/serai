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
  /// The block this header builds upon.
  pub parent_hash: BlockHash,
  /// The UNIX time in milliseconds this block was created at.
  pub unix_time_in_millis: u64,
  /// The root of a Merkle tree commiting to the transactions within this block.
  // TODO: Review the format of this defined by Substrate. We don't want to commit to the signature
  // TODO: Some transactions don't have unique hashes due to assuming vaalidators set unique keys
  pub transactions_root: [u8; 32],
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
  /// Get the hash of the header.
  pub fn parent_hash(&self) -> BlockHash {
    match self {
      Header::V1(HeaderV1 { parent_hash, .. }) => *parent_hash,
    }
  }
  /// Get the hash of the header.
  pub fn transactions_root(&self) -> [u8; 32] {
    match self {
      Header::V1(HeaderV1 { transactions_root, .. }) => *transactions_root,
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
  use scale::{Encode, Decode};
  use scale_info::TypeInfo;

  use sp_core::H256;
  use sp_runtime::{
    generic::Digest,
    traits::{Header as HeaderTrait, HeaderProvider, Block as BlockTrait},
  };

  use super::*;

  /// The consensus data for a V1 header.
  ///
  /// This is not considered part of the protocol proper and may be pruned in the future. It's
  /// solely considered used for consensus now.
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, sp_runtime::Serialize)]
  pub struct ConsensusV1 {
    /// The state root.
    state_root: H256,
    /// The consensus digests.
    digest: Digest,
  }

  /// A V1 header for a block, as needed by Substrate.
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, sp_runtime::Serialize)]
  pub struct SubstrateHeaderV1 {
    number: u64,
    parent_hash: H256,
    transactions_root: H256,
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
      use sp_consensus_babe::SlotDuration;
      use sc_consensus_babe::CompatibleDigestItem;

      match header {
        SubstrateHeader::V1(header) => Header::V1(HeaderV1 {
          number: header.number,
          parent_hash: BlockHash(header.parent_hash.0),
          unix_time_in_millis: header
            .consensus
            .digest
            .logs()
            .iter()
            .find_map(|digest_item| {
              digest_item.as_babe_pre_digest().map(|pre_digest| {
                pre_digest
                  .slot()
                  .timestamp(SlotDuration::from_millis(
                    serai_primitives::constants::TARGET_BLOCK_TIME.as_millis().try_into().unwrap(),
                  ))
                  // This returns `None` if the slot is so far in the future, it'd cause an
                  // overflow.
                  .unwrap_or(sp_timestamp::Timestamp::new(u64::MAX))
                  .as_millis()
              })
            })
            .unwrap_or(0),
          transactions_root: header.transactions_root.0,
          consensus_commitment: sp_core::blake2_256(&header.consensus.encode()),
        }),
      }
    }
  }

  /// A block, as needed by Substrate.
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, sp_runtime::Serialize)]
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
        parent_hash,
        transactions_root: extrinsics_root,
        consensus: ConsensusV1 { state_root, digest },
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
        SubstrateHeader::V1(SubstrateHeaderV1 { transactions_root, .. }) => transactions_root,
      }
    }
    fn set_extrinsics_root(&mut self, extrinsics_root: Self::Hash) {
      match self {
        SubstrateHeader::V1(SubstrateHeaderV1 { transactions_root, .. }) => {
          *transactions_root = extrinsics_root;
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
        SubstrateHeader::V1(SubstrateHeaderV1 { parent_hash, .. }) => parent_hash,
      }
    }
    fn set_parent_hash(&mut self, parent_hash: Self::Hash) {
      match self {
        SubstrateHeader::V1(SubstrateHeaderV1 { parent_hash: existing, .. }) => {
          *existing = parent_hash;
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
