use std::{
  collections::{HashMap, HashSet},
  sync::Arc,
  time::{SystemTime, UNIX_EPOCH},
};

use blake2::{Blake2b256, Digest as _};
use tokio::sync::RwLock;

use serai_abi::{
  Block, Event, Header, HeaderV1, BLOCK_BRANCH_TAG, BLOCK_LEAF_TAG,
  primitives::{
    BlockHash,
    balance::Amount,
    crypto::KeyPair,
    merkle::{IncrementalUnbalancedMerkleTree, UnbalancedMerkleTree},
    network_id::{ExternalNetworkId, NetworkId},
    validator_sets::{ExternalValidatorSet, Session},
    address::SeraiAddress,
  },
};

/// Per-block validator-sets state.
#[derive(Clone, Debug, Default)]
pub struct ValidatorSetsState {
  pub sessions: HashMap<NetworkId, Session>,
  pub stakes: HashMap<NetworkId, Amount>,
  pub keys: HashMap<ExternalValidatorSet, KeyPair>,
  pub validators: HashMap<NetworkId, Vec<SeraiAddress>>,
  pub pending_slash_reports: HashMap<ExternalNetworkId, bool>,
}

/// Injectable failures at three levels.
#[derive(Clone, Debug, Default)]
pub struct ErrorInjection {
  /// Any call to the method fails with this message.
  pub method_errors: HashMap<String, String>,
  /// Fails for a specific block number.
  pub block_number_errors: HashMap<(String, u64), String>,
  /// Fails for a specific block hash.
  pub block_hash_errors: HashMap<(String, BlockHash), String>,
}

impl ErrorInjection {
  /// Check if an error should be injected for this method call.
  pub fn check_method(&self, method: &str) -> Option<&String> {
    self.method_errors.get(method)
  }

  /// Check if an error should be injected for this method + block number.
  pub fn check_block_number(&self, method: &str, number: u64) -> Option<&String> {
    self.block_number_errors.get(&(method.to_owned(), number))
  }

  /// Check if an error should be injected for this method + block hash.
  pub fn check_block_hash(&self, method: &str, hash: &BlockHash) -> Option<&String> {
    self.block_hash_errors.get(&(method.to_owned(), *hash))
  }
}

/// The shared mutable state backing the shim RPC node.
pub struct ShimState {
  pub blocks_by_number: HashMap<u64, Block>,
  pub block_number_by_hash: HashMap<BlockHash, u64>,
  pub events_by_hash: HashMap<BlockHash, Vec<Vec<Event>>>,
  pub builds_upon: IncrementalUnbalancedMerkleTree,
  pub published_transactions: Vec<Vec<u8>>,
  pub default_validator_sets: ValidatorSetsState,
  pub validator_sets_by_block: HashMap<BlockHash, ValidatorSetsState>,
  pub errors: ErrorInjection,
  /// Block numbers that `blockchain/block` should return `None` for (simulates "not found").
  pub missing_blocks: HashSet<u64>,
}

impl Default for ShimState {
  fn default() -> Self {
    Self {
      blocks_by_number: HashMap::new(),
      block_number_by_hash: HashMap::new(),
      events_by_hash: HashMap::new(),
      builds_upon: IncrementalUnbalancedMerkleTree::new(),
      published_transactions: Vec::new(),
      default_validator_sets: ValidatorSetsState::default(),
      validator_sets_by_block: HashMap::new(),
      errors: ErrorInjection::default(),
      missing_blocks: HashSet::new(),
    }
  }
}

impl ShimState {
  /// Construct a block and register it. Mirrors `FakeSerai::make_block` from intend.rs.
  pub fn make_block(&mut self, number: u64, events: Vec<Vec<Event>>) -> BlockHash {
    let block = Block {
      header: Header::V1(HeaderV1 {
        number,
        builds_upon: self.builds_upon.clone().calculate(BLOCK_BRANCH_TAG),
        proposer: SeraiAddress([0; 32]),
        #[expect(clippy::cast_possible_truncation, clippy::as_conversions)]
        unix_time_in_millis: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis()
          as u64,
        transactions_commitment: UnbalancedMerkleTree::EMPTY,
        events_commitment: UnbalancedMerkleTree::EMPTY,
        consensus_commitment: [0; 32],
      }),
      transactions: vec![],
    };

    let block_hash = block.header.hash();

    self.builds_upon.append(
      BLOCK_BRANCH_TAG,
      Blake2b256::new_with_prefix([BLOCK_LEAF_TAG]).chain_update(block_hash.0).finalize().into(),
    );

    self.block_number_by_hash.insert(block_hash, number);
    self.blocks_by_number.insert(number, block);
    self.events_by_hash.insert(block_hash, events);

    block_hash
  }

  /// The latest finalized block number, or 0 if no blocks exist.
  pub fn latest_finalized_block_number(&self) -> u64 {
    self.blocks_by_number.keys().copied().max().unwrap_or(0)
  }

  /// Create a block whose `builds_upon` header value comes from an empty tree,
  /// making it invalid with respect to the actual chain.
  ///
  /// Unlike [`Self::make_block`], this does **not** advance the internal
  /// `builds_upon` state, so subsequent calls to `make_block` remain valid.
  pub fn make_non_linear_block(
    &mut self,
    number: u64,
    events: Vec<Vec<Event>>,
  ) -> BlockHash {
    let block = Block {
      header: Header::V1(HeaderV1 {
        number,
        // Use an empty tree — this will NOT match what the task expects
        builds_upon: IncrementalUnbalancedMerkleTree::new().calculate(BLOCK_BRANCH_TAG),
        proposer: SeraiAddress([0; 32]),
        #[expect(clippy::cast_possible_truncation, clippy::as_conversions)]
        unix_time_in_millis: SystemTime::now()
          .duration_since(UNIX_EPOCH)
          .unwrap()
          .as_millis() as u64,
        transactions_commitment: UnbalancedMerkleTree::EMPTY,
        events_commitment: UnbalancedMerkleTree::EMPTY,
        consensus_commitment: [0; 32],
      }),
      transactions: vec![],
    };

    let block_hash = block.header.hash();

    // Register the block but do NOT update builds_upon
    self.block_number_by_hash.insert(block_hash, number);
    self.blocks_by_number.insert(number, block);
    self.events_by_hash.insert(block_hash, events);

    block_hash
  }

  /// Remove a block from all maps.
  pub fn remove_block(&mut self, number: u64) {
    if let Some(block) = self.blocks_by_number.remove(&number) {
      let hash = block.header.hash();
      self.block_number_by_hash.remove(&hash);
      self.events_by_hash.remove(&hash);
    }
  }

  /// Look up a block hash by block number.
  pub fn block_hash_by_number(&self, number: u64) -> Option<BlockHash> {
    self.blocks_by_number.get(&number).map(|block| block.header.hash())
  }

  /// Get the validator-sets state for a specific block, falling back to the default.
  pub fn validator_sets_for_block(&self, hash: &BlockHash) -> &ValidatorSetsState {
    self.validator_sets_by_block.get(hash).unwrap_or(&self.default_validator_sets)
  }
}

/// Thread-safe shared state handle.
pub type SharedState = Arc<RwLock<ShimState>>;
