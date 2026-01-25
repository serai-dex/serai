use core::fmt::Debug;

use scale::{Encode, EncodeLike, Decode, DecodeAll as _, DecodeWithMemTracking};

use sp_core::{
  serde::{Serialize, Serializer, Deserialize},
  H256,
};
use sp_runtime::{
  generic::{DigestItem, Digest},
  traits::{Header as HeaderTrait, HeaderProvider, LazyExtrinsic, LazyBlock, Block as BlockTrait},
};

use super::*;

/// The digest for all of the Serai-specific header fields added before execution of the block.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct SeraiPreExecutionDigest {
  /// The proposer of this block.
  pub proposer: SeraiAddress,
  /// The UNIX time in milliseconds this block was created at.
  pub unix_time_in_millis: u64,
}

impl SeraiPreExecutionDigest {
  /// The consensus ID for a Serai pre-execution digest.
  pub const CONSENSUS_ID: [u8; 4] = *b"SRIP";

  /// Find the pre-execution digest within a `Digest`.
  ///
  /// This will panic if the digest either isn't found or is invalid.
  pub fn find(digest: &Digest) -> Self {
    for log in digest.logs() {
      #[expect(clippy::wildcard_enum_match_arm)]
      match log {
        DigestItem::PreRuntime(consensus, encoded)
          if *consensus == SeraiPreExecutionDigest::CONSENSUS_ID =>
        {
          return <_>::deserialize_reader(&mut encoded.as_slice())
            .expect("invalid `SeraiPreExecutionDigest`");
        }
        _ => {}
      }
    }
    panic!("missing `SeraiPreExecutionDigest`");
  }
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

impl SeraiExecutionDigest {
  /// The consensus ID for a Serai execution digest.
  pub const CONSENSUS_ID: [u8; 4] = *b"SRIE";
}

/// The consensus data for a V1 header.
///
/// This is not considered part of the protocol proper and may be pruned in the future. It's
/// solely considered used for consensus currently.
#[derive(
  Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, Serialize, Deserialize,
)]
#[serde(crate = "sp_core::serde")]
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
  Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, Serialize, Deserialize,
)]
#[serde(crate = "sp_core::serde")]
pub struct SubstrateHeaderV1 {
  number: u64,
  consensus: ConsensusV1,
}

/// A header for a block, as needed by Substrate.
#[derive(
  Clone, PartialEq, Eq, Debug, Encode, Decode, DecodeWithMemTracking, Serialize, Deserialize,
)]
#[serde(crate = "sp_core::serde")]
pub enum SubstrateHeader {
  /// A version 1 header.
  V1(SubstrateHeaderV1),
}

impl From<&SubstrateHeader> for Header {
  /// If any fields are missing, default values will be stubbed.
  fn from(header: &SubstrateHeader) -> Self {
    match header {
      SubstrateHeader::V1(header) => {
        let mut pre_execution_digest = None;
        let mut execution_digest = None;
        for log in header.consensus.digest.logs() {
          #[expect(clippy::wildcard_enum_match_arm)]
          match log {
            DigestItem::PreRuntime(consensus, encoded)
              if *consensus == SeraiPreExecutionDigest::CONSENSUS_ID =>
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
          proposer: pre_execution_digest
            .as_ref()
            .map(|digest| digest.proposer)
            .unwrap_or(SeraiAddress([0; 32])),
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
///
/// This _DOES NOT_ enforce [`Block::MAX_SIZE`] on decode.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode, DecodeWithMemTracking)]
pub struct SubstrateBlock {
  header: SubstrateHeader,
  transactions: Vec<Transaction>,
}

impl From<SubstrateBlock> for Block {
  /// This may create a potentially over-sized [`Block`].
  fn from(block: SubstrateBlock) -> Self {
    Self { header: (&block.header).into(), transactions: block.transactions }
  }
}

/*
  `Block` and `Block::Extrinsic` must implement `MaybeSerialize` so we implement a
  `serde::Serialize` which treats `self` as an opaque `Vec<u8>`.
*/
impl Serialize for Transaction {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    <Vec<u8> as Serialize>::serialize(&self.encode(), serializer)
  }
}
impl Serialize for SubstrateBlock {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    <Vec<u8> as Serialize>::serialize(&self.encode(), serializer)
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

// These `trait` implementations are required to implement `Block for SubstrateBlock`
impl LazyExtrinsic for Transaction {
  fn decode_unprefixed(mut data: &[u8]) -> Result<Self, scale::Error> {
    Transaction::decode_all(&mut data)
  }
}
#[expect(clippy::from_over_into)] // We don't want this and solely have this to satisfy Substrate
impl Into<sp_runtime::OpaqueExtrinsic> for Transaction {
  fn into(self) -> sp_runtime::OpaqueExtrinsic {
    sp_runtime::OpaqueExtrinsic::from_blob(self.encode())
  }
}

/// A block type which satisfies the [`LazyBlock`] trait.
///
/// We stub this for now, forgoing the optimization enabled by this being a distinct type in
/// favor of the simplicity.
#[derive(Debug, Encode, Decode)]
pub struct LazySubstrateBlock(SubstrateBlock);

#[expect(clippy::from_over_into)]
impl Into<LazySubstrateBlock> for SubstrateBlock {
  fn into(self) -> LazySubstrateBlock {
    LazySubstrateBlock(self)
  }
}

impl EncodeLike<SubstrateBlock> for LazySubstrateBlock {}
impl EncodeLike<LazySubstrateBlock> for SubstrateBlock {}

impl LazyBlock for LazySubstrateBlock {
  type Extrinsic = Transaction;
  type Header = SubstrateHeader;
  fn header(&self) -> &Self::Header {
    &self.0.header
  }
  fn header_mut(&mut self) -> &mut Self::Header {
    &mut self.0.header
  }
  fn extrinsics(&self) -> impl Iterator<Item = Result<Self::Extrinsic, scale::Error>> {
    self.0.transactions.iter().cloned().map(Ok)
  }
}

impl BlockTrait for SubstrateBlock {
  type Extrinsic = Transaction;
  type Header = SubstrateHeader;
  type Hash = H256;
  type LazyBlock = LazySubstrateBlock;
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
  fn hash(&self) -> Self::Hash {
    self.header.hash()
  }
}

#[test]
fn find_serai_pre_execution_digest() {
  use alloc::vec;
  use rand_core::{RngCore as _, OsRng};

  let mut digest = Digest { logs: vec![] };
  let push = |digest: &mut Digest| {
    for _ in 0 .. (OsRng.next_u64() % 8) {
      digest.push(if (OsRng.next_u64() & 1) == 1 {
        let mut bytes = vec![0; (OsRng.next_u64() % 512) as usize];
        OsRng.fill_bytes(&mut bytes);
        DigestItem::Other(bytes)
      } else {
        let mut consensus_id = [0; 4];
        OsRng.fill_bytes(&mut consensus_id);
        let mut bytes = vec![0; (OsRng.next_u64() % 512) as usize];
        OsRng.fill_bytes(&mut bytes);
        DigestItem::PreRuntime(consensus_id, bytes)
      });
    }
  };
  push(&mut digest);

  let mut proposer = [0; 32];
  OsRng.fill_bytes(&mut proposer);
  let proposer = SeraiAddress(proposer);
  let serai_pre_execution_digest =
    SeraiPreExecutionDigest { proposer, unix_time_in_millis: OsRng.next_u64() };
  digest.push(DigestItem::PreRuntime(
    SeraiPreExecutionDigest::CONSENSUS_ID,
    borsh::to_vec(&serai_pre_execution_digest).unwrap(),
  ));
  push(&mut digest);
  assert_eq!(SeraiPreExecutionDigest::find(&digest), serai_pre_execution_digest);
}

#[test]
fn header_from_substrate_header() {
  use alloc::vec;
  use rand_core::{RngCore as _, OsRng};

  let mut proposer = [0; 32];
  OsRng.fill_bytes(&mut proposer);
  let proposer = SeraiAddress(proposer);
  let unix_time_in_millis = OsRng.next_u64();

  let serai_pre_execution_digest = DigestItem::PreRuntime(
    SeraiPreExecutionDigest::CONSENSUS_ID,
    borsh::to_vec(&SeraiPreExecutionDigest { proposer, unix_time_in_millis }).unwrap(),
  );

  let mut builds_upon = [0; 32];
  OsRng.fill_bytes(&mut builds_upon);
  let builds_upon = UnbalancedMerkleTree { root: builds_upon };

  let mut transactions_commitment = [0; 32];
  OsRng.fill_bytes(&mut transactions_commitment);
  let transactions_commitment = UnbalancedMerkleTree { root: transactions_commitment };

  let mut events_commitment = [0; 32];
  OsRng.fill_bytes(&mut events_commitment);
  let events_commitment = UnbalancedMerkleTree { root: events_commitment };

  let serai_execution_digest = DigestItem::Consensus(
    SeraiExecutionDigest::CONSENSUS_ID,
    borsh::to_vec(&SeraiExecutionDigest {
      builds_upon,
      transactions_commitment,
      events_commitment,
    })
    .unwrap(),
  );

  let substrate_header = |logs| {
    let substrate_header =
      SubstrateHeader::new(0, [0; 32].into(), [0; 32].into(), [0; 32].into(), Digest { logs });
    let consensus_commitment = match &substrate_header {
      SubstrateHeader::V1(substrate_header) => {
        sp_core::blake2_256(&substrate_header.consensus.encode())
      }
    };
    (Header::from(&substrate_header), consensus_commitment)
  };

  // Without any digests
  {
    let (substrate_header, consensus_commitment) = substrate_header(vec![]);
    assert_eq!(
      substrate_header,
      Header::V1(HeaderV1 {
        number: 0,
        builds_upon: UnbalancedMerkleTree::EMPTY,
        proposer: SeraiAddress([0; 32]),
        unix_time_in_millis: 0,
        transactions_commitment: UnbalancedMerkleTree::EMPTY,
        events_commitment: UnbalancedMerkleTree::EMPTY,
        consensus_commitment,
      })
    );
  }

  // With solely `SeraiPreExecutionDigest`
  {
    let (substrate_header, consensus_commitment) =
      substrate_header(vec![serai_pre_execution_digest.clone()]);
    assert_eq!(
      substrate_header,
      Header::V1(HeaderV1 {
        number: 0,
        builds_upon: UnbalancedMerkleTree::EMPTY,
        proposer,
        unix_time_in_millis,
        transactions_commitment: UnbalancedMerkleTree::EMPTY,
        events_commitment: UnbalancedMerkleTree::EMPTY,
        consensus_commitment,
      })
    );
  }

  // With solely `SeraiExecutionDigest`
  {
    let (substrate_header, consensus_commitment) =
      substrate_header(vec![serai_execution_digest.clone()]);
    assert_eq!(
      substrate_header,
      Header::V1(HeaderV1 {
        number: 0,
        builds_upon,
        proposer: SeraiAddress([0; 32]),
        unix_time_in_millis: 0,
        transactions_commitment,
        events_commitment,
        consensus_commitment,
      })
    );
  }

  // With both digests
  {
    let (substrate_header, consensus_commitment) =
      substrate_header(vec![serai_pre_execution_digest, serai_execution_digest]);
    assert_eq!(
      substrate_header,
      Header::V1(HeaderV1 {
        number: 0,
        builds_upon,
        proposer,
        unix_time_in_millis,
        transactions_commitment,
        events_commitment,
        consensus_commitment,
      })
    );
  }
}

#[test]
fn header_trait() {
  use alloc::vec;
  use rand_core::{RngCore as _, OsRng};

  let mut header = SubstrateHeader::new(
    0,
    [0; 32].into(),
    [0; 32].into(),
    [0; 32].into(),
    Digest { logs: vec![] },
  );
  for _ in 0 .. 2 {
    {
      let number = OsRng.next_u64();
      header.set_number(number);
      assert_eq!(*header.number(), number);
    }

    {
      let mut extrinsics_root = [0; 32];
      OsRng.fill_bytes(&mut extrinsics_root);
      let extrinsics_root = extrinsics_root.into();
      header.set_extrinsics_root(extrinsics_root);
      assert_eq!(*header.extrinsics_root(), extrinsics_root);
    }

    {
      let mut state_root = [0; 32];
      OsRng.fill_bytes(&mut state_root);
      let state_root = state_root.into();
      header.set_state_root(state_root);
      assert_eq!(*header.state_root(), state_root);
    }

    {
      let mut parent_hash = [0; 32];
      OsRng.fill_bytes(&mut parent_hash);
      let parent_hash = parent_hash.into();
      header.set_parent_hash(parent_hash);
      assert_eq!(*header.parent_hash(), parent_hash);
    }

    {
      let mut digest = header.digest().clone();
      let mut bytes = vec![0; (OsRng.next_u64() % 512) as usize];
      OsRng.fill_bytes(&mut bytes);
      let digest_item = DigestItem::Other(bytes);

      digest.push(digest_item.clone());
      header.digest_mut().push(digest_item);

      assert_eq!(&digest, header.digest());
    }

    assert_eq!(Header::from(&header).hash(), header.hash().into());
  }
}
