//! Test helpers for verifying database invariants.
//!
//! Provides the [`VerifyDbInvariants`] trait, a minimal default abstraction for
//! verifying database state in tests, and the [`ChannelDrainAsserter`] utility
//! for asserting the state of [`db_channel!`](crate::db_channel)-generated
//! channels.

use core::future::Future;
use std::collections::HashMap;

use crate::{Db as _, MemDb, MemDbTxn};

use serai_client_serai::Serai;

/// Trait for verifying database invariants in tests.
///
/// Implementors define a [`State`](Self::State) type for tracking expected
/// database state and override [`verify_db_invariants`](Self::verify_db_invariants)
/// with their own invariant checks.
///
/// Block replay is optional.
pub trait VerifyDbInvariants {
  /// State type used for tracking expected database state during invariant
  /// verification.
  type State;

  /// Process a single block during replay, updating the replay state.
  ///
  /// Override this to implement custom per-block replay logic.
  fn replay_block(
    _state: &mut Self::State,
    _serai: &Serai,
    _block_num: u64,
  ) -> impl Send + Future<Output = ()>
  where
    Self::State: Send,
  {
    async move { Default::default() }
  }

  /// Replay blocks from `0 .. num_blocks`, calling [`replay_block`](Self::replay_block)
  /// for each block.
  fn replay_blocks(
    state: &mut Self::State,
    serai: &Serai,
    num_blocks: u64,
  ) -> impl Send + Future<Output = ()>
  where
    Self::State: Send,
  {
    async move {
      for block_num in 0 .. num_blocks {
        Self::replay_block(state, serai, block_num).await;
      }
    }
  }

  /// Verify database invariants against the replayed state.
  ///
  /// Implementors should override this with their own checks, asserting the
  /// database state matches expectations.
  fn verify_db_invariants(db: &mut MemDb, state: &Self::State) -> impl Send + Future<Output = ()>;
}

/// Reusable utilities for asserting the state of `db_channel!`-generated
/// channels in tests.
pub struct ChannelDrainAsserter;
impl ChannelDrainAsserter {
  /// Drain an unkeyed channel into a `Vec` via repeated `try_recv` calls.
  pub fn drain_all<T, F>(db: &mut MemDb, mut try_recv: F) -> Vec<T>
  where
    F: FnMut(&mut MemDbTxn<'_>) -> Option<T>,
  {
    let mut txn = db.txn();
    let mut items = Vec::new();
    while let Some(item) = try_recv(&mut txn) {
      items.push(item);
    }
    items
  }

  /// Drain a keyed channel per key in `expected` into a `HashMap<K, Vec<T>>`.
  ///
  /// For each key in `expected`, opens a transaction and drains the channel
  /// for that key via `try_recv_for(&key, &mut txn)` until `try_recv` returns
  /// `None`. Keys are returned in the order they were drained.
  pub fn drain_keys<K, T, F>(
    db: &mut MemDb,
    expected: impl IntoIterator<Item = K>,
    mut try_recv_for: F,
  ) -> HashMap<K, Vec<T>>
  where
    K: Eq + std::hash::Hash,
    F: FnMut(&K, &mut MemDbTxn<'_>) -> Option<T>,
  {
    let mut by_key = HashMap::new();
    for key in expected {
      let mut txn = db.txn();
      let mut items = Vec::new();
      while let Some(item) = try_recv_for(&key, &mut txn) {
        items.push(item);
      }
      by_key.insert(key, items);
    }
    by_key
  }
}
