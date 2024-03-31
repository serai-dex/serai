use std::{io, collections::HashSet};

use ciphersuite::Ciphersuite;

use serai_client::primitives::{NetworkId, Coin, Balance};

use crate::{
  networks::{Output, Network},
  Db, Payment, Plan,
};

#[derive(PartialEq, Eq, Debug)]
pub struct Scheduler<N: Network>(<N::Curve as Ciphersuite>::G, HashSet<Coin>);

impl<N: Network> crate::multisigs::scheduler::Scheduler<N> for Scheduler<N> {
  /// Check if this Scheduler is empty.
  fn empty(&self) -> bool {
    true
  }

  /// Create a new Scheduler.
  fn new<D: Db>(
    _txn: &mut D::Transaction<'_>,
    key: <N::Curve as Ciphersuite>::G,
    network: NetworkId,
  ) -> Self {
    Scheduler(key, network.coins().iter().copied().collect())
  }

  /// Load a Scheduler from the DB.
  fn from_db<D: Db>(
    _db: &D,
    key: <N::Curve as Ciphersuite>::G,
    network: NetworkId,
  ) -> io::Result<Self> {
    Ok(Scheduler(key, network.coins().iter().copied().collect()))
  }

  fn can_use_branch(&self, _balance: Balance) -> bool {
    false
  }

  fn schedule<D: Db>(
    &mut self,
    _txn: &mut D::Transaction<'_>,
    utxos: Vec<N::Output>,
    payments: Vec<Payment<N>>,
    _key_for_any_change: <N::Curve as Ciphersuite>::G,
    _force_spend: bool,
  ) -> Vec<Plan<N>> {
    for utxo in utxos {
      assert!(self.1.contains(&utxo.balance().coin));
    }

    let mut plans = vec![];
    for chunk in payments.as_slice().chunks(N::MAX_OUTPUTS) {
      plans.push(Plan { key: self.0, inputs: vec![], payments: chunk.to_vec(), change: None });
    }
    plans
  }

  fn consume_payments<D: Db>(&mut self, _txn: &mut D::Transaction<'_>) -> Vec<Payment<N>> {
    vec![]
  }

  fn created_output<D: Db>(
    &mut self,
    _txn: &mut D::Transaction<'_>,
    _expected: u64,
    _actual: Option<u64>,
  ) {
    panic!("Account Scheduler created a Branch output")
  }
}
