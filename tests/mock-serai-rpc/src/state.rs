//! Shared mutable state backing the mock Serai RPC node.

use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
  time::SystemTime,
  fmt::Write as _,
};

use rand_core::{RngCore as _, OsRng};

use blake2::{Digest as _, Blake2b256};

use serai_abi::{
  primitives::{
    BlockHash,
    crypto::KeyPair,
    merkle::{UnbalancedMerkleTree, IncrementalUnbalancedMerkleTree},
    address::SeraiAddress,
    network_id::{ExternalNetworkId, NetworkId},
    validator_sets::{Session, ExternalValidatorSet},
    balance::Amount,
  },
  BLOCK_LEAF_TAG, BLOCK_BRANCH_TAG, HeaderV1, Header, Block, Event,
};

use tokio::sync::RwLock;

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
  /// Probability (0–100) that any request randomly fails. 0 = never, 100 = always.
  pub failure_rate: u8,
}

impl ErrorInjection {
  /// Check if this request should randomly fail based on the configured `failure_rate`.
  pub fn check_random_failure(&self, method: &str) -> Option<String> {
    ((OsRng.next_u32() % 100) < u32::from(self.failure_rate))
      .then(|| format!("fuzz: random failure on `{method}` (rate={}%)", self.failure_rate))
  }

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

/// The shared mutable state backing the mock Serai RPC node.
pub struct MockSeraiState {
  pub blocks_by_number: HashMap<u64, Block>,
  pub block_number_by_hash: HashMap<BlockHash, u64>,
  pub events_by_hash: HashMap<BlockHash, Vec<Event>>,
  pub builds_upon: IncrementalUnbalancedMerkleTree,
  pub published_transactions: Vec<Vec<u8>>,
  pub default_validator_sets: ValidatorSetsState,
  pub validator_sets_by_block: HashMap<BlockHash, ValidatorSetsState>,
  pub errors: ErrorInjection,
  /// Block numbers that `blockchain/block` should return `None` for (simulates "not found").
  pub missing_blocks: HashSet<u64>,
}

impl Default for MockSeraiState {
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

impl MockSeraiState {
  /// Construct a block and register it.
  pub fn make_block(
    &mut self,
    number: u64,
    events: Vec<Vec<Event>>,
  ) -> (BlockHash, Vec<Event>, Block) {
    let block = Block {
      header: Header::V1(HeaderV1 {
        number,
        builds_upon: self.builds_upon.clone().calculate(BLOCK_BRANCH_TAG),
        proposer: SeraiAddress([0; 32]),
        unix_time_in_millis: u64::try_from(
          SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis(),
        )
        .unwrap(),
        transactions_commitment: UnbalancedMerkleTree::EMPTY,
        // TODO: Properly populate `events_commitment`
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

    let events: Vec<Event> = events.into_iter().flatten().collect();
    self.block_number_by_hash.insert(block_hash, number);
    self.blocks_by_number.insert(number, block.clone());
    self.events_by_hash.insert(block_hash, events.clone());

    // Per-block logging when MOCK_SERAI_DUMP_BLOCKS=1
    if Self::dump_env_enabled() {
      let event_count = events.len();
      serai_env::log::info!(
        "[MOCK_SERAI] block #{number} (hash: 0x{}, {} event(s))",
        hex::encode(block_hash.0),
        event_count,
      );
      for (i, event) in events.iter().enumerate() {
        serai_env::log::info!("[MOCK_SERAI]   [{i}] {event:?}");
      }
    }

    (block_hash, events, block)
  }

  /// The latest finalized block number.
  pub fn latest_finalized_block_number(&self) -> Option<u64> {
    self.blocks_by_number.keys().copied().max()
  }

  /// Create a block whose `builds_upon` header value differs from any valid chain value
  /// by flipping a single bit, making it invalid with respect to the actual chain.
  ///
  /// Unlike [`Self::make_block`], this does **not** advance the internal
  /// `builds_upon` state, so subsequent calls to `make_block` remain valid.
  pub fn make_non_linear_block(
    &mut self,
    number: u64,
    events: Vec<Vec<Event>>,
  ) -> (BlockHash, Vec<Event>, Block) {
    let mut builds_upon_root = self.builds_upon.clone().calculate(BLOCK_BRANCH_TAG).root;
    builds_upon_root[0] ^= 1; // Flip bit 0 to create a near-valid but non-chain root
    let builds_upon = UnbalancedMerkleTree { root: builds_upon_root };

    let block = Block {
      header: Header::V1(HeaderV1 {
        number,
        builds_upon,
        proposer: SeraiAddress([0; 32]),
        unix_time_in_millis: u64::try_from(
          SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_millis(),
        )
        .unwrap(),
        transactions_commitment: UnbalancedMerkleTree::EMPTY,
        events_commitment: UnbalancedMerkleTree::EMPTY,
        consensus_commitment: [0; 32],
      }),
      transactions: vec![],
    };

    let block_hash = block.header.hash();

    let events: Vec<Event> = events.into_iter().flatten().collect();
    // Register the block but do not update builds_upon
    self.block_number_by_hash.insert(block_hash, number);
    self.blocks_by_number.insert(number, block.clone());
    self.events_by_hash.insert(block_hash, events.clone());

    // Per-block logging when MOCK_SERAI_DUMP_BLOCKS=1
    if Self::dump_env_enabled() {
      let event_count = events.len();
      serai_env::log::info!(
        "[MOCK_SERAI] non-linear block #{number} (hash: 0x{}, {} event(s))",
        hex::encode(block_hash.0),
        event_count,
      );
      for (i, event) in events.iter().enumerate() {
        serai_env::log::info!("[MOCK_SERAI]   [{i}] {event:?}");
      }
    }

    (block_hash, events, block)
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

  /// Return a human-readable dump of all blocks and their events as a single string.
  ///
  /// Useful for embedding in assertion failure messages or logging on test failure.
  pub fn dump_blocks(&self) -> String {
    let mut out = String::new();
    let count = self.blocks_by_number.len();

    // Collect and sort block numbers
    let mut numbers: Vec<u64> = self.blocks_by_number.keys().copied().collect();
    numbers.sort_unstable();

    let _ = writeln!(out, "--- Mock Serai block dump ({count} blocks) ---");
    for &number in &numbers {
      let block = &self.blocks_by_number[&number];
      let hash = block.header.hash();
      let events = self.events_by_hash.get(&hash).map(std::vec::Vec::as_slice).unwrap_or(&[]);
      let _ = writeln!(
        out,
        "block #{number} (hash: 0x{}): {} events",
        hex::encode(hash.0),
        events.len(),
      );
      for (i, event) in events.iter().enumerate() {
        let _ = writeln!(out, "  [{i}] {event:?}");
      }
    }
    out
  }

  /// Log all blocks and their events via the `log` crate at INFO level.
  ///
  /// Controlled by the `MOCK_SERAI_DUMP_BLOCKS` env var: if set to `"1"` this method is
  /// automatically called whenever a block is created via [`make_block`](Self::make_block).
  pub fn log_dump(&self) {
    serai_env::log::info!("{}", self.dump_blocks());
  }

  /// Check whether per-block logging is enabled via `MOCK_SERAI_DUMP_BLOCKS`.
  fn dump_env_enabled() -> bool {
    serai_env::var("MOCK_SERAI_DUMP_BLOCKS").as_deref().is_some()
  }
}

/// Thread-safe shared state handle.
pub type SharedState = Arc<RwLock<MockSeraiState>>;
