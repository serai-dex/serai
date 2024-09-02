#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::marker::PhantomData;
use std::collections::HashMap;

use group::GroupEncoding;

use serai_primitives::Coin;

use serai_db::DbTxn;

use primitives::{ReceivedOutput, Payment};
use scanner::{
  LifetimeStage, ScannerFeed, KeyFor, AddressFor, OutputFor, EventualityFor, SchedulerUpdate,
  Scheduler as SchedulerTrait,
};
use scheduler_primitives::*;
use utxo_scheduler_primitives::*;

mod db;
use db::Db;

/// A planned transaction.
pub struct PlannedTransaction<S: ScannerFeed, T> {
  /// The signable transaction.
  signable: T,
  /// The outputs we'll receive from this.
  effected_received_outputs: OutputFor<S>,
  /// The Eventuality to watch for.
  eventuality: EventualityFor<S>,
}

/// A scheduler of transactions for networks premised on the UTXO model which support
/// transaction chaining.
pub struct Scheduler<
  S: ScannerFeed,
  T,
  P: TransactionPlanner<S, PlannedTransaction = PlannedTransaction<S, T>>,
>(PhantomData<S>, PhantomData<T>, PhantomData<P>);

impl<S: ScannerFeed, T, P: TransactionPlanner<S, PlannedTransaction = PlannedTransaction<S, T>>>
  Scheduler<S, T, P>
{
  fn accumulate_outputs(txn: &mut impl DbTxn, key: KeyFor<S>, outputs: &[OutputFor<S>]) {
    // Accumulate them in memory
    let mut outputs_by_coin = HashMap::with_capacity(1);
    for output in outputs.iter().filter(|output| output.key() == key) {
      let coin = output.balance().coin;
      if let std::collections::hash_map::Entry::Vacant(e) = outputs_by_coin.entry(coin) {
        e.insert(Db::<S>::outputs(txn, key, coin).unwrap());
      }
      outputs_by_coin.get_mut(&coin).unwrap().push(output.clone());
    }

    // Flush them to the database
    for (coin, outputs) in outputs_by_coin {
      Db::<S>::set_outputs(txn, key, coin, &outputs);
    }
  }
}

impl<
    S: ScannerFeed,
    T: 'static + Send + Sync + SignableTransaction,
    P: TransactionPlanner<S, PlannedTransaction = PlannedTransaction<S, T>>,
  > SchedulerTrait<S> for Scheduler<S, T, P>
{
  fn activate_key(&mut self, txn: &mut impl DbTxn, key: KeyFor<S>) {
    for coin in S::NETWORK.coins() {
      Db::<S>::set_outputs(txn, key, *coin, &[]);
    }
  }

  fn flush_key(&mut self, txn: &mut impl DbTxn, retiring_key: KeyFor<S>, new_key: KeyFor<S>) {
    todo!("TODO")
  }

  fn retire_key(&mut self, txn: &mut impl DbTxn, key: KeyFor<S>) {
    for coin in S::NETWORK.coins() {
      assert!(Db::<S>::outputs(txn, key, *coin).is_none());
      Db::<S>::del_outputs(txn, key, *coin);
    }
  }

  fn update(
    &mut self,
    txn: &mut impl DbTxn,
    active_keys: &[(KeyFor<S>, LifetimeStage)],
    update: SchedulerUpdate<S>,
  ) -> HashMap<Vec<u8>, Vec<EventualityFor<S>>> {
    // Accumulate all the outputs
    for key in active_keys {
      Self::accumulate_outputs(txn, key.0, update.outputs());
    }

    let mut fee_rates: HashMap<Coin, _> = todo!("TODO");

    // Create the transactions for the forwards/burns
    {
      let mut planned_txs = vec![];
      for forward in update.forwards() {
        let key = forward.key();

        assert_eq!(active_keys.len(), 2);
        assert_eq!(active_keys[0].1, LifetimeStage::Forwarding);
        assert_eq!(active_keys[1].1, LifetimeStage::Active);
        let forward_to_key = active_keys[1].0;

        let Some(plan) = P::plan_transaction_with_fee_amortization(
          // This uses 0 for the operating costs as we don't incur any here
          &mut 0,
          fee_rates[&forward.balance().coin],
          vec![forward.clone()],
          vec![Payment::new(P::forwarding_address(forward_to_key), forward.balance(), None)],
          None,
        ) else {
          continue;
        };
        planned_txs.push((key, plan));
      }
      for to_return in update.returns() {
        let key = to_return.output().key();
        let out_instruction =
          Payment::new(to_return.address().clone(), to_return.output().balance(), None);
        let Some(plan) = P::plan_transaction_with_fee_amortization(
          // This uses 0 for the operating costs as we don't incur any here
          &mut 0,
          fee_rates[&out_instruction.balance().coin],
          vec![to_return.output().clone()],
          vec![out_instruction],
          None,
        ) else {
          continue;
        };
        planned_txs.push((key, plan));
      }

      let mut eventualities = HashMap::new();
      for (key, planned_tx) in planned_txs {
        // Send the transactions off for signing
        TransactionsToSign::<T>::send(txn, &key, &planned_tx.signable);

        // Insert the eventualities into the result
        eventualities
          .entry(key.to_bytes().as_ref().to_vec())
          .or_insert(Vec::with_capacity(1))
          .push(planned_tx.eventuality);
      }

      // TODO: Fulfill any payments we prior couldn't

      eventualities
    }
  }

  fn fulfill(
    &mut self,
    txn: &mut impl DbTxn,
    active_keys: &[(KeyFor<S>, LifetimeStage)],
    payments: Vec<Payment<AddressFor<S>>>,
  ) -> HashMap<Vec<u8>, Vec<EventualityFor<S>>> {
    // TODO: Find the key to use for fulfillment
    // TODO: Sort outputs and payments by amount
    // TODO: For as long as we don't have sufficiently aggregated inputs to handle all payments,
    // aggregate
    // TODO: Create the tree for the payments
    todo!("TODO")
  }
}
