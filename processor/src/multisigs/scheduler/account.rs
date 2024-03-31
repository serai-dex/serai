use std::{io, collections::HashSet};

use ciphersuite::{group::GroupEncoding, Ciphersuite};

use serai_client::primitives::{NetworkId, Coin, Balance};

use crate::{
  networks::{Output, Network},
  Get, DbTxn, Db, Payment, Plan, create_db,
};

#[derive(PartialEq, Eq, Debug)]
pub struct Scheduler<N: Network>(<N::Curve as Ciphersuite>::G, HashSet<Coin>, bool);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Nonce(pub u64);

create_db! {
  SchedulerDb {
    LastNonce: () -> u64,
    UpdatedKey: (key: &[u8]) -> (),
  }
}

impl<N: Network> crate::multisigs::scheduler::Scheduler<N> for Scheduler<N>
where
  N::Output: From<Nonce>,
{
  /// Check if this Scheduler is empty.
  fn empty(&self) -> bool {
    self.2
  }

  /// Create a new Scheduler.
  fn new<D: Db>(
    _txn: &mut D::Transaction<'_>,
    key: <N::Curve as Ciphersuite>::G,
    network: NetworkId,
  ) -> Self {
    Scheduler(key, network.coins().iter().copied().collect(), false)
  }

  /// Load a Scheduler from the DB.
  fn from_db<D: Db>(
    db: &D,
    key: <N::Curve as Ciphersuite>::G,
    network: NetworkId,
  ) -> io::Result<Self> {
    Ok(Scheduler(
      key,
      network.coins().iter().copied().collect(),
      UpdatedKey::get(db, key.to_bytes().as_ref()).is_some(),
    ))
  }

  fn can_use_branch(&self, _balance: Balance) -> bool {
    false
  }

  fn schedule<D: Db>(
    &mut self,
    txn: &mut D::Transaction<'_>,
    utxos: Vec<N::Output>,
    mut payments: Vec<Payment<N>>,
    key_for_any_change: <N::Curve as Ciphersuite>::G,
    force_spend: bool,
  ) -> Vec<Plan<N>> {
    for utxo in utxos {
      assert!(self.1.contains(&utxo.balance().coin));
    }

    // Drop payments to addresses which aren't our external address (and aren't used here)
    {
      let branch_address = N::branch_address(self.0);
      let change_address = N::change_address(self.0);
      let forward_address = N::forward_address(self.0);
      payments = payments
        .drain(..)
        .filter(|payment| {
          (payment.address != branch_address) &&
            (payment.address != change_address) &&
            (payment.address != forward_address)
        })
        .collect::<Vec<_>>();
    }

    let mut nonce = LastNonce::get(txn).map_or(0, |nonce| nonce + 1);
    let mut plans = vec![];
    for chunk in payments.as_slice().chunks(N::MAX_OUTPUTS) {
      plans.push(Plan {
        key: self.0,
        inputs: vec![N::Output::from(Nonce(nonce))],
        payments: chunk.to_vec(),
        change: None,
      });
      nonce += 1;
    }
    LastNonce::set(txn, &nonce);

    // If we're supposed to rotate to the new key, create an empty Plan which will signify the key
    // update
    if force_spend && (!self.2) {
      plans.push(Plan {
        key: self.0,
        inputs: vec![],
        payments: vec![],
        change: Some(N::external_address(key_for_any_change)),
      });
      self.2 = true;
      UpdatedKey::set(txn, self.0.to_bytes().as_ref(), &());
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
