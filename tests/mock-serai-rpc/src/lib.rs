//! Top-level mock Serai RPC node implementation.

#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

use std::{net::SocketAddr, sync::Arc};

use rand_core::{CryptoRng, RngCore};

pub use serai_env::test_helpers::{TestRng, new_test_rng};
use serai_abi::{
  Block, Event,
  primitives::{
    crypto::KeyPair,
    network_id::{ExternalNetworkId, NetworkId},
    validator_sets::{ExternalValidatorSet, Session},
    BlockHash,
  },
};
use serai_primitives::merkle::IncrementalUnbalancedMerkleTree;

use crate::block_events_fuzzer::BlockEventsFuzzer;

use jsonrpsee::server::ServerBuilder;
use tokio::sync::RwLock;

pub mod state;
pub mod rpc;
pub mod test_helpers;
pub mod events;

pub mod block_events_fuzzer;
pub mod event_fuzzer;

pub use state::*;

/// A bespoke mock Serai RPC node that speaks JSON-RPC 2.0 over HTTP,
/// wire-compatible with the production `Serai` client.
pub struct MockSeraiRpc {
  url: String,
  state: SharedState,
}

impl MockSeraiRpc {
  /// Start a mock Serai RPC node with the given initial state, binding to an ephemeral port.
  pub async fn start(initial_state: MockSeraiState) -> Self {
    let state = Arc::new(RwLock::new(initial_state));
    let rpc_module = rpc::build_rpc_module(state.clone()).expect("failed to build RPC module");

    let server = ServerBuilder::default()
      .build(SocketAddr::from(([127, 0, 0, 1], 0)))
      .await
      .expect("failed to bind mock Serai RPC node server");

    let addr = server.local_addr().expect("server should have a local address");

    core::mem::forget(server.start(rpc_module));

    Self { url: format!("http://{addr}"), state }
  }

  /// Setup and start a mock Serai RPC as well as returning the Serai API using it as source.
  pub async fn setup_mock_serai() -> (MockSeraiRpc, Arc<serai_client_serai::Serai>) {
    let mock_serai = MockSeraiRpc::start(MockSeraiState::default()).await;
    let serai_api = Arc::new(serai_client_serai::Serai::new(mock_serai.url.clone()).unwrap());
    (mock_serai, serai_api)
  }

  /// Generate `num_blocks` random blocks using an internal [`BlockEventsFuzzer`].
  /// Returns block hashes paired with block numbers, events per block, and full block objects.
  pub async fn fuzz_blocks<R: RngCore + CryptoRng>(
    &self,
    fuzzer: &mut BlockEventsFuzzer<R>,
    num_blocks: usize,
  ) -> (Vec<(u64, BlockHash)>, Vec<Vec<Event>>, Vec<Block>) {
    let blocks = fuzzer.generate_blocks(num_blocks);
    let mut block_hashes = Vec::with_capacity(num_blocks);
    let mut all_events = Vec::with_capacity(num_blocks);
    let mut all_blocks = Vec::with_capacity(num_blocks);
    for events in blocks {
      let number = self.next_block().await;
      let (hash, returned_events, block) = self.add_block_with_events(events).await;
      block_hashes.push((number, hash));
      all_events.push(returned_events);
      all_blocks.push(block);
    }
    (block_hashes, all_events, all_blocks)
  }

  /// Generate `num_blocks` random blocks using an internal [`BlockEventsFuzzer`].
  /// Returns block hashes paired with block numbers, events per block, and full block objects.
  ///
  /// Pass the coordinator's own address in `extra_validators` to allow `in_set` to return true,
  /// exercising the `NewSet` message path in the coordinator.
  pub async fn fuzz_blocks_with_validators<R: RngCore + CryptoRng>(
    &self,
    fuzzer: &mut BlockEventsFuzzer<R>,
    num_blocks: usize,
  ) -> (Vec<(u64, BlockHash)>, Vec<Vec<Event>>, Vec<Block>) {
    let blocks = fuzzer.generate_blocks(num_blocks);
    let mut block_hashes = Vec::with_capacity(num_blocks);
    let mut all_events = Vec::with_capacity(num_blocks);
    let mut all_blocks = Vec::with_capacity(num_blocks);
    for events in blocks {
      let number = self.next_block().await;
      let (hash, returned_events, block) = self.add_block_with_events(events).await;
      block_hashes.push((number, hash));
      all_events.push(returned_events);
      all_blocks.push(block);
    }
    (block_hashes, all_events, all_blocks)
  }

  /// Generate `num_blocks` random blocks using an internal [`BlockEventsFuzzer`].
  /// Returns block hashes paired with block numbers, events per block, and full block objects.
  pub async fn fuzz_blocks_up_to<R: RngCore + CryptoRng>(
    &self,
    fuzzer: &mut BlockEventsFuzzer<R>,
    up_to_blocks: usize,
  ) -> (Vec<(u64, BlockHash)>, Vec<Vec<Event>>, Vec<Block>) {
    // From 1 up to ...N blocks *can* be generated
    let num_blocks = (usize::try_from(fuzzer.rng.next_u64()).unwrap() % up_to_blocks) + 1;
    self.fuzz_blocks(fuzzer, num_blocks).await
  }

  /// Add a block with events dynamically (during a test).
  /// The block number is automatically determined as the next sequential block.
  /// Returns the hash of the newly created block.
  pub async fn last_block(&self) -> u64 {
    let state = self.state.read().await;
    state.latest_finalized_block_number().unwrap_or(0)
  }

  /// Add a block with events dynamically (during a test).
  /// The block number is automatically determined as the next sequential block.
  /// Returns the hash of the newly created block.
  pub async fn next_block(&self) -> u64 {
    let state = self.state.read().await;
    state.latest_finalized_block_number().map(|latest_block| latest_block + 1).unwrap_or(0)
  }

  /// Add a block with events dynamically (during a test).
  /// The block number is automatically determined as the next sequential block.
  /// Returns the hash of the newly created block.
  pub async fn add_block_with_events(
    &self,
    events: Vec<Vec<Event>>,
  ) -> (BlockHash, Vec<Event>, Block) {
    let next_block = self.next_block().await;
    let mut state = self.state.write().await;
    state.make_block(next_block, events)
  }

  /// Get the mock Serai node's current `builds_upon` merkle tree state.
  pub async fn builds_upon(&self) -> IncrementalUnbalancedMerkleTree {
    self.state.read().await.builds_upon.clone()
  }

  /// Inject an error for a specific RPC method. Any call to this method will fail.
  pub async fn set_error(&self, method: &str, message: &str) {
    let mut state = self.state.write().await;
    state.errors.method_errors.insert(method.to_owned(), message.to_owned());
  }

  /// Inject an error for a specific RPC method + block number combination.
  pub async fn set_block_number_error(&self, method: &str, number: u64, message: &str) {
    let mut state = self.state.write().await;
    state.errors.block_number_errors.insert((method.to_owned(), number), message.to_owned());
  }

  /// Clear an injected error for a specific RPC method + block number.
  pub async fn clear_block_number_error(&self, method: &str, number: u64) {
    let mut state = self.state.write().await;
    state.errors.block_number_errors.remove(&(method.to_owned(), number));
  }

  /// Inject an error for a specific RPC method + block hash combination.
  pub async fn set_block_hash_error(&self, method: &str, hash: BlockHash, message: &str) {
    let mut state = self.state.write().await;
    state.errors.block_hash_errors.insert((method.to_owned(), hash), message.to_owned());
  }

  /// Clear an injected error for a specific RPC method + block hash.
  pub async fn clear_block_hash_error(&self, method: &str, hash: BlockHash) {
    let mut state = self.state.write().await;
    state.errors.block_hash_errors.remove(&(method.to_owned(), hash));
  }

  /// Hide a block so that `blockchain/block` returns `None` for it.
  pub async fn set_block_missing(&self, number: u64) {
    self.state.write().await.missing_blocks.insert(number);
  }

  /// Un-hide a previously hidden block.
  pub async fn clear_block_missing(&self, number: u64) {
    self.state.write().await.missing_blocks.remove(&number);
  }

  /// Clear an injected error for a specific RPC method.
  pub async fn clear_error(&self, method: &str) {
    let mut state = self.state.write().await;
    state.errors.method_errors.remove(method);
  }

  /// Clear all injected errors.
  pub async fn clear_all_errors(&self) {
    let mut state = self.state.write().await;
    state.errors = ErrorInjection::default();
  }

  /// Remove a block (and its associated events) from the mock Serai node state.
  pub async fn remove_block(&self, number: u64) {
    let mut state = self.state.write().await;
    state.remove_block(number);
  }

  /// Create a non-linear block (wrong `builds_upon`) without advancing the chain state.
  pub async fn make_non_linear_block(
    &self,
    number: u64,
    events: Vec<Vec<Event>>,
  ) -> (BlockHash, Vec<Event>, Block) {
    let mut state = self.state.write().await;
    state.make_non_linear_block(number, events)
  }

  /// Return a human-readable dump of all created blocks and their events.
  ///
  /// Useful for embedding in assertion messages or logging on test failure.
  pub async fn dump_blocks(&self) -> String {
    self.state.read().await.dump_blocks()
  }

  /// Log all created blocks and their events at INFO level.
  ///
  /// Useful to call at the end of a test on failure.
  pub async fn log_dump(&self) {
    self.state.read().await.log_dump();
  }

  /// Set the probability (0–100) that any RPC request randomly fails.
  ///
  /// 0 disables fuzzing (the default), 100 fails every request.
  /// If the `SERAI_MOCK_RPC_NO_ERROR` env var is set, the rate is forced to 0.
  pub async fn set_failure_rate(&self, percent: u8) {
    let effective = if serai_env::var("SERAI_MOCK_RPC_NO_ERROR").is_some() { 0 } else { percent };
    self.state.write().await.errors.failure_rate = effective;
  }

  /// Disable random request failures.
  pub async fn clear_failure_rate(&self) {
    self.state.write().await.errors.failure_rate = 0;
  }

  /// Set the current session for a given network in the mock state.
  pub async fn set_session(&self, network: NetworkId, session: Session) {
    self.state.write().await.default_validator_sets.sessions.insert(network, session);
  }

  /// Set the key pair for a given external validator set in the mock state.
  pub async fn set_key(&self, set: ExternalValidatorSet, key_pair: KeyPair) {
    self.state.write().await.default_validator_sets.keys.insert(set, key_pair);
  }

  /// Set the pending-slash-report flag for a given external network.
  pub async fn set_pending_slash_report(&self, network: ExternalNetworkId, pending: bool) {
    self.state.write().await.default_validator_sets.pending_slash_reports.insert(network, pending);
  }
}
