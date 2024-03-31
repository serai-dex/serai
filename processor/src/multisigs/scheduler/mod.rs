use core::fmt::Debug;
use std::io;

use ciphersuite::Ciphersuite;

use serai_client::primitives::{Coin, Balance};

use crate::{networks::Network, Db, Payment, Plan};

pub(crate) mod utxo;

pub trait Scheduler<N: Network>: Sized + PartialEq + Debug {
  /// Check if this Scheduler is empty.
  fn empty(&self) -> bool;

  /// Create a new Scheduler.
  fn new<D: Db>(
    txn: &mut D::Transaction<'_>,
    key: <N::Curve as Ciphersuite>::G,
    coin: Coin,
  ) -> Self;

  /// Load a Scheduler from the DB.
  fn from_db<D: Db>(db: &D, key: <N::Curve as Ciphersuite>::G, coin: Coin) -> io::Result<Self>;

  /// Check if a branch is usable.
  fn can_use_branch(&self, balance: Balance) -> bool;

  /// Schedule a series of outputs/payments.
  fn schedule<D: Db>(
    &mut self,
    txn: &mut D::Transaction<'_>,
    utxos: Vec<N::Output>,
    payments: Vec<Payment<N>>,
    key_for_any_change: <N::Curve as Ciphersuite>::G,
    force_spend: bool,
  ) -> Vec<Plan<N>>;

  /// Consume all payments still pending within this Scheduler, without scheduling them.
  fn consume_payments<D: Db>(&mut self, txn: &mut D::Transaction<'_>) -> Vec<Payment<N>>;

  /// Note a branch output as having been created, with the amount it was actually created with,
  /// or not having been created due to being too small.
  fn created_output<D: Db>(
    &mut self,
    txn: &mut D::Transaction<'_>,
    expected: u64,
    actual: Option<u64>,
  );
}

impl<N: Network> Scheduler<N> for utxo::Scheduler<N> {
  /// Check if this Scheduler is empty.
  fn empty(&self) -> bool {
    utxo::Scheduler::empty(self)
  }

  /// Create a new Scheduler.
  fn new<D: Db>(
    txn: &mut D::Transaction<'_>,
    key: <N::Curve as Ciphersuite>::G,
    coin: Coin,
  ) -> Self {
    utxo::Scheduler::new::<D>(txn, key, coin)
  }

  /// Load a Scheduler from the DB.
  fn from_db<D: Db>(db: &D, key: <N::Curve as Ciphersuite>::G, coin: Coin) -> io::Result<Self> {
    utxo::Scheduler::from_db::<D>(db, key, coin)
  }

  /// Check if a branch is usable.
  fn can_use_branch(&self, balance: Balance) -> bool {
    utxo::Scheduler::can_use_branch(self, balance)
  }

  /// Schedule a series of outputs/payments.
  fn schedule<D: Db>(
    &mut self,
    txn: &mut D::Transaction<'_>,
    utxos: Vec<N::Output>,
    payments: Vec<Payment<N>>,
    key_for_any_change: <N::Curve as Ciphersuite>::G,
    force_spend: bool,
  ) -> Vec<Plan<N>> {
    utxo::Scheduler::schedule::<D>(self, txn, utxos, payments, key_for_any_change, force_spend)
  }

  /// Consume all payments still pending within this Scheduler, without scheduling them.
  fn consume_payments<D: Db>(&mut self, txn: &mut D::Transaction<'_>) -> Vec<Payment<N>> {
    utxo::Scheduler::consume_payments::<D>(self, txn)
  }

  /// Note a branch output as having been created, with the amount it was actually created with,
  /// or not having been created due to being too small.
  fn created_output<D: Db>(
    &mut self,
    txn: &mut D::Transaction<'_>,
    expected: u64,
    actual: Option<u64>,
  ) {
    utxo::Scheduler::created_output::<D>(self, txn, expected, actual)
  }
}
