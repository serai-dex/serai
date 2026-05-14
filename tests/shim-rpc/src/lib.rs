#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

use std::{sync::Arc, net::SocketAddr};

use serai_abi::{
  primitives::{BlockHash, merkle::IncrementalUnbalancedMerkleTree},
  Event,
};

use jsonrpsee::server::{ServerBuilder, ServerHandle};
use tokio::sync::RwLock;

pub mod state;
pub mod rpc;
pub mod builder;
pub mod test_helpers;

pub mod event_fuzzer;

pub use state::*;
pub use builder::SeraiShimRpcBuilder;

/// A bespoke shim RPC node that speaks JSON-RPC 2.0 over HTTP,
/// wire-compatible with the production `Serai` client.
pub struct SeraiShimRpc {
  url: String,
  state: SharedState,
  _handle: ServerHandle,
}

impl SeraiShimRpc {
  /// Create a builder for configuring and starting a shim RPC node.
  pub fn builder() -> SeraiShimRpcBuilder {
    SeraiShimRpcBuilder::new()
  }

  /// Start a shim RPC node with the given initial state, binding to an ephemeral port.
  pub async fn start(initial_state: ShimState) -> Self {
    let state = Arc::new(RwLock::new(initial_state));
    let rpc_module = rpc::build_rpc_module(state.clone()).expect("failed to build RPC module");

    let server = ServerBuilder::default()
      .build(SocketAddr::from(([127, 0, 0, 1], 0)))
      .await
      .expect("failed to bind shim RPC node server");

    let addr = server.local_addr().expect("server should have a local address");
    Self { url: format!("http://{addr}"), state, _handle: server.start(rpc_module) }
  }

  /// The HTTP URL this shim is listening on.
  pub fn url(&self) -> String {
    self.url.clone()
  }

  /// Create a block at the given number with events.
  /// Returns the hash of the newly created block.
  pub async fn make_block(&self, number: u64, events: Vec<Vec<Event>>) -> BlockHash {
    self.state.write().await.make_block(number, events)
  }

  /// Add a block with events dynamically (during a test).
  /// The block number is automatically determined as the next sequential block.
  /// Returns the hash of the newly created block.
  pub async fn add_block_with_events(&self, events: Vec<Vec<Event>>) -> BlockHash {
    let mut state = self.state.write().await;
    let number =
      state.latest_finalized_block_number().map(|latest_block| latest_block + 1).unwrap_or(0);
    state.make_block(number, events)
  }

  /// Get the shim's current `builds_upon` merkle tree state.
  pub async fn builds_upon(&self) -> IncrementalUnbalancedMerkleTree {
    self.state.read().await.builds_upon.clone()
  }

  /// Inject an error for a specific RPC method. Any call to this method will fail.
  pub async fn set_error(&self, method: &str, message: &str) {
    let mut state = self.state.write().await;
    state.errors.method_errors.insert(method.to_owned(), message.to_owned());
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

  /// Remove a block (and its associated events) from the shim state.
  pub async fn remove_block(&self, number: u64) {
    let mut state = self.state.write().await;
    state.remove_block(number);
  }

  /// Create a non-linear block (wrong `builds_upon`) without advancing the chain state.
  pub async fn make_non_linear_block(&self, number: u64, events: Vec<Vec<Event>>) -> BlockHash {
    let mut state = self.state.write().await;
    state.make_non_linear_block(number, events)
  }

  /// Access the underlying shared state directly.
  pub fn state(&self) -> &SharedState {
    &self.state
  }

  /// Set the probability (0–100) that any RPC request randomly fails.
  ///
  /// 0 disables fuzzing (the default), 100 fails every request.
  pub async fn set_failure_rate(&self, percent: u8) {
    self.state.write().await.errors.failure_rate = percent;
  }

  /// Disable random request failures.
  pub async fn clear_failure_rate(&self) {
    self.state.write().await.errors.failure_rate = 0;
  }
}
