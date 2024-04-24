use core::fmt::Debug;
use std::io;

use ciphersuite::Ciphersuite;

use serai_client::primitives::{NetworkId, Balance};

use crate::{networks::Network, Db, Payment, Plan};

pub(crate) mod utxo;
pub(crate) mod smart_contract;

pub trait SchedulerAddendum: Send + Clone + PartialEq + Debug {
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self>;
  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()>;
}

impl SchedulerAddendum for () {
  fn read<R: io::Read>(_: &mut R) -> io::Result<Self> {
    Ok(())
  }
  fn write<W: io::Write>(&self, _: &mut W) -> io::Result<()> {
    Ok(())
  }
}

pub trait Scheduler<N: Network>: Sized + Clone + PartialEq + Debug {
  type Addendum: SchedulerAddendum;

  /// Check if this Scheduler is empty.
  fn empty(&self) -> bool;

  /// Create a new Scheduler.
  fn new<D: Db>(
    txn: &mut D::Transaction<'_>,
    key: <N::Curve as Ciphersuite>::G,
    network: NetworkId,
  ) -> Self;

  /// Load a Scheduler from the DB.
  fn from_db<D: Db>(
    db: &D,
    key: <N::Curve as Ciphersuite>::G,
    network: NetworkId,
  ) -> io::Result<Self>;

  /// Check if a branch is usable.
  fn can_use_branch(&self, balance: Balance) -> bool;

  /// Schedule a series of outputs/payments.
  fn schedule<D: Db>(
    &mut self,
    txn: &mut D::Transaction<'_>,
    utxos: Vec<N::Output>,
    payments: Vec<Payment<N>>,
    // TODO: Tighten this to multisig_for_any_change
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

  /// Refund a specific output.
  fn refund_plan<D: Db>(
    &mut self,
    txn: &mut D::Transaction<'_>,
    output: N::Output,
    refund_to: N::Address,
  ) -> Plan<N>;

  /// Shim the forwarding Plan as necessary to obtain a fee estimate.
  ///
  /// If this Scheduler is for a Network which requires forwarding, this must return Some with a
  /// plan with identical fee behavior. If forwarding isn't necessary, returns None.
  fn shim_forward_plan(output: N::Output, to: <N::Curve as Ciphersuite>::G) -> Option<Plan<N>>;

  /// Forward a specific output to the new multisig.
  ///
  /// Returns None if no forwarding is necessary. Must return Some if forwarding is necessary.
  fn forward_plan<D: Db>(
    &mut self,
    txn: &mut D::Transaction<'_>,
    output: N::Output,
    to: <N::Curve as Ciphersuite>::G,
  ) -> Option<Plan<N>>;
}
