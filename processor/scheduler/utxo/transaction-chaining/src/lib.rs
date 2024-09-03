#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::marker::PhantomData;
use std::collections::HashMap;

use group::GroupEncoding;

use serai_primitives::{Coin, Amount, Balance};

use serai_db::DbTxn;

use primitives::{OutputType, ReceivedOutput, Payment};
use scanner::{
  LifetimeStage, ScannerFeed, KeyFor, AddressFor, OutputFor, EventualityFor, SchedulerUpdate,
  Scheduler as SchedulerTrait,
};
use scheduler_primitives::*;
use utxo_scheduler_primitives::*;

mod db;
use db::Db;

/// The outputs which will be effected by a PlannedTransaction and received by Serai.
pub struct EffectedReceivedOutputs<S: ScannerFeed>(Vec<OutputFor<S>>);

/// A scheduler of transactions for networks premised on the UTXO model which support
/// transaction chaining.
pub struct Scheduler<S: ScannerFeed, P: TransactionPlanner<S, EffectedReceivedOutputs<S>>>(
  PhantomData<S>,
  PhantomData<P>,
);

impl<S: ScannerFeed, P: TransactionPlanner<S, EffectedReceivedOutputs<S>>> Scheduler<S, P> {
  fn handle_queued_payments(
    &mut self,
    txn: &mut impl DbTxn,
    active_keys: &[(KeyFor<S>, LifetimeStage)],
    key: KeyFor<S>,
  ) -> Vec<EventualityFor<S>> {
    let mut eventualities = vec![];

    let mut accumulate_outputs = |txn, outputs: Vec<OutputFor<S>>| {
      let mut outputs_by_key = HashMap::new();
      for output in outputs {
        Db::<S>::set_already_accumulated_output(txn, output.id());
        let coin = output.balance().coin;
        outputs_by_key
          .entry((output.key().to_bytes().as_ref().to_vec(), coin))
          .or_insert_with(|| (output.key(), Db::<S>::outputs(txn, output.key(), coin).unwrap()))
          .1
          .push(output);
      }
      for ((_key_vec, coin), (key, outputs)) in outputs_by_key {
        Db::<S>::set_outputs(txn, key, coin, &outputs);
      }
    };

    for coin in S::NETWORK.coins() {
      // Fetch our operating costs and all our outputs
      let mut operating_costs = Db::<S>::operating_costs(txn, *coin).0;
      let mut outputs = Db::<S>::outputs(txn, key, *coin).unwrap();

      // If we have more than the maximum amount of inputs, aggregate until we don't
      {
        while outputs.len() > MAX_INPUTS {
          let Some(planned) = P::plan_transaction_with_fee_amortization(
            &mut operating_costs,
            fee_rates[coin],
            outputs.drain(.. MAX_INPUTS).collect::<Vec<_>>(),
            vec![],
            Some(key_for_change),
          ) else {
            // We amortized all payments, and even when just trying to make the change output, these
            // inputs couldn't afford their own aggregation and were written off
            Db::<S>::set_operating_costs(txn, *coin, Amount(operating_costs));
            continue;
          };

          // Send the transactions off for signing
          TransactionsToSign::<P::SignableTransaction>::send(txn, &key, &planned.signable);
          // Push the Eventualities onto the result
          eventualities.push(planned.eventuality);
          // Accumulate the outputs
          Db::set_outputs(txn, key, *coin, &outputs);
          accumulate_outputs(txn, planned.auxilliary.0);
          outputs = Db::outputs(txn, key, *coin).unwrap();
        }
        Db::<S>::set_operating_costs(txn, *coin, Amount(operating_costs));
      }

      // Now, handle the payments
      let mut payments = Db::<S>::queued_payments(txn, key, *coin).unwrap();
      if payments.is_empty() {
        continue;
      }

      // If this is our only key, our outputs and operating costs should be greater than the
      // payments' value
      if active_keys.len() == 1 {
        // The available amount to fulfill is the amount we have plus the amount we'll reduce by
        // An alternative formulation would be `outputs >= (payments - operating costs)`, but
        // that'd risk underflow
        let value_available =
          operating_costs + outputs.iter().map(|output| output.balance().amount.0).sum::<u64>();

        assert!(
          value_available >= payments.iter().map(|payment| payment.balance().amount.0).sum::<u64>()
        );
      }

      // Find the set of payments we should fulfill at this time
      loop {
        let value_available =
          operating_costs + outputs.iter().map(|output| output.balance().amount.0).sum::<u64>();

        // Drop to just the payments we currently have the outputs for
        {
          let mut can_handle = 0;
          let mut value_used = 0;
          for payment in payments {
            value_used += payment.balance().amount.0;
            if value_available < value_used {
              break;
            }
            can_handle += 1;
          }

          let remaining_payments = payments.drain(can_handle ..).collect::<Vec<_>>();
          // Restore the rest to the database
          Db::<S>::set_queued_payments(txn, key, *coin, &remaining_payments);
        }
        let payments_value = payments.iter().map(|payment| payment.balance().amount.0).sum::<u64>();

        // If these payments are worth less than the operating costs, immediately drop them
        if payments_value <= operating_costs {
          operating_costs -= payments_value;
          Db::<S>::set_operating_costs(txn, *coin, Amount(operating_costs));

          // Reset payments to the queued payments
          payments = Db::<S>::queued_payments(txn, key, *coin).unwrap();
          // If there's no more payments, stop looking for which payments we should fulfill
          if payments.is_empty() {
            break;
          }

          // Find which of these we should handle
          continue;
        }

        break;
      }
      if payments.is_empty() {
        continue;
      }

      // Create a tree to fulfill all of the payments
      struct TreeTransaction<S: ScannerFeed> {
        payments: Vec<Payment<AddressFor<S>>>,
        children: Vec<TreeTransaction<S>>,
        value: u64,
      }
      let mut tree_transactions = vec![];
      for payments in payments.chunks(MAX_OUTPUTS) {
        let value = payments.iter().map(|payment| payment.balance().amount.0).sum::<u64>();
        tree_transactions.push(TreeTransaction::<S> {
          payments: payments.to_vec(),
          children: vec![],
          value,
        });
      }
      // While we haven't calculated a tree root, or the tree root doesn't support a change output,
      // keep working
      while (tree_transactions.len() != 1) || (tree_transactions[0].payments.len() == MAX_OUTPUTS) {
        let mut next_tree_transactions = vec![];
        for children in tree_transactions.chunks(MAX_OUTPUTS) {
          let payments = children
            .iter()
            .map(|child| {
              Payment::new(
                P::branch_address(key),
                Balance { coin: *coin, amount: Amount(child.value) },
                None,
              )
            })
            .collect();
          let value = children.iter().map(|child| child.value).sum();
          next_tree_transactions.push(TreeTransaction {
            payments,
            children: children.to_vec(),
            value,
          });
        }
        tree_transactions = next_tree_transactions;
      }
      assert_eq!(tree_transactions.len(), 1);
      assert!((tree_transactions.payments.len() + 1) <= MAX_OUTPUTS);

      // Create the transaction for the root of the tree
      let Some(planned) = P::plan_transaction_with_fee_amortization(
        &mut operating_costs,
        fee_rates[coin],
        outputs,
        tree_transactions.payments,
        Some(key_for_change),
      ) else {
        Db::<S>::set_operating_costs(txn, *coin, Amount(operating_costs));
        continue;
      };
      TransactionsToSign::<P::SignableTransaction>::send(txn, &key, &planned.signable);
      eventualities.push(planned.eventuality);

      // We accumulate the change output, but consume the branches here
      accumulate_outputs(
        txn,
        planned
          .auxilliary
          .0
          .iter()
          .filter(|output| output.kind() == OutputType::Change)
          .cloned()
          .collect(),
      );
      // Filter the outputs to the change outputs
      let mut branch_outputs = planned.auxilliary.0;
      branch_outputs.retain(|output| output.kind() == OutputType::Branch);

      // This is recursive, yet only recurses with logarithmic depth
      let execute_tree_transaction = |branch_outputs, children| {
        assert_eq!(branch_outputs.len(), children.len());

        // Sort the branch outputs by their value
        branch_outputs.sort_by(|a, b| a.balance().amount.0.cmp(&b.balance().amount.0));
        // Find the child for each branch output
        // This is only done within a transaction, not across the layer, so we don't have branches
        // created in transactions with less outputs (and therefore less fees) jump places with
        // other branches
        children.sort_by(|a, b| a.value.cmp(&b.value));

        for (branch_output, child) in branch_outputs.into_iter().zip(children) {
          assert_eq!(branch_output.kind(), OutputType::Branch);
          Db::<S>::set_already_accumulated_output(txn, branch_output.id());

          let Some(planned) = P::plan_transaction_with_fee_amortization(
            // Uses 0 as there's no operating costs to incur/amortize here
            &mut 0,
            fee_rates[coin],
            vec![branch_output],
            child.payments,
            None,
          ) else {
            // This Branch isn't viable, so drop it (and its children)
            continue;
          };
          TransactionsToSign::<P::SignableTransaction>::send(txn, &key, &planned.signable);
          eventualities.push(planned.eventuality);
          if !child.children.is_empty() {
            execute_tree_transaction(planned.auxilliary.0, child.children);
          }
        }
      };
      if !tree_transaction.children.is_empty() {
        execute_tree_transaction(branch_outputs, tree_transaction.children);
      }
    }

    eventualities
  }
}

impl<S: ScannerFeed, P: TransactionPlanner<S, EffectedReceivedOutputs<S>>> SchedulerTrait<S>
  for Scheduler<S, P>
{
  fn activate_key(&mut self, txn: &mut impl DbTxn, key: KeyFor<S>) {
    for coin in S::NETWORK.coins() {
      assert!(Db::<S>::outputs(txn, key, *coin).is_none());
      Db::<S>::set_outputs(txn, key, *coin, &[]);
      assert!(Db::<S>::queued_payments(txn, key, *coin).is_none());
      Db::<S>::set_queued_payments(txn, key, *coin, &vec![]);
    }
  }

  fn flush_key(&mut self, txn: &mut impl DbTxn, retiring_key: KeyFor<S>, new_key: KeyFor<S>) {
    for coin in S::NETWORK.coins() {
      let still_queued = Db::<S>::queued_payments(txn, retiring_key, *coin).unwrap();
      let mut new_queued = Db::<S>::queued_payments(txn, new_key, *coin).unwrap();

      let mut queued = still_queued;
      queued.append(&mut new_queued);

      Db::<S>::set_queued_payments(txn, retiring_key, *coin, &vec![]);
      Db::<S>::set_queued_payments(txn, new_key, *coin, &queued);
    }
  }

  fn retire_key(&mut self, txn: &mut impl DbTxn, key: KeyFor<S>) {
    for coin in S::NETWORK.coins() {
      assert!(Db::<S>::outputs(txn, key, *coin).unwrap().is_empty());
      Db::<S>::del_outputs(txn, key, *coin);
      assert!(Db::<S>::queued_payments(txn, key, *coin).unwrap().is_empty());
      Db::<S>::del_queued_payments(txn, key, *coin);
    }
  }

  fn update(
    &mut self,
    txn: &mut impl DbTxn,
    active_keys: &[(KeyFor<S>, LifetimeStage)],
    update: SchedulerUpdate<S>,
  ) -> HashMap<Vec<u8>, Vec<EventualityFor<S>>> {
    // Accumulate all the outputs
    for (key, _) in active_keys {
      // Accumulate them in memory
      let mut outputs_by_coin = HashMap::with_capacity(1);
      for output in update.outputs().iter().filter(|output| output.key() == *key) {
        match output.kind() {
          OutputType::External | OutputType::Forwarded => {}
          // Only accumulate these if we haven't already
          OutputType::Branch | OutputType::Change => {
            if Db::<S>::take_if_already_accumulated_output(txn, output.id()) {
              continue;
            }
          }
        }
        let coin = output.balance().coin;
        if let std::collections::hash_map::Entry::Vacant(e) = outputs_by_coin.entry(coin) {
          e.insert(Db::<S>::outputs(txn, *key, coin).unwrap());
        }
        outputs_by_coin.get_mut(&coin).unwrap().push(output.clone());
      }

      // Flush them to the database
      for (coin, outputs) in outputs_by_coin {
        Db::<S>::set_outputs(txn, *key, coin, &outputs);
      }
    }

    let mut fee_rates: HashMap<Coin, _> = todo!("TODO");

    // Fulfill the payments we prior couldn't
    let mut eventualities = HashMap::new();
    for (key, _stage) in active_keys {
      eventualities.insert(
        key.to_bytes().as_ref().to_vec(),
        self.handle_queued_payments(txn, active_keys, *key),
      );
    }

    // TODO: If this key has been flushed, forward all outputs

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
          // If the output can't pay for itself to be forwarded, we simply drop it
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
          // If the output can't pay for itself to be returned, we simply drop it
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

      for (key, planned_tx) in planned_txs {
        // Send the transactions off for signing
        TransactionsToSign::<P::SignableTransaction>::send(txn, &key, &planned_tx.signable);

        // Insert the Eventualities into the result
        eventualities[key.to_bytes().as_ref()].push(planned_tx.eventuality);
      }

      eventualities
    }
  }

  fn fulfill(
    &mut self,
    txn: &mut impl DbTxn,
    active_keys: &[(KeyFor<S>, LifetimeStage)],
    mut payments: Vec<Payment<AddressFor<S>>>,
  ) -> HashMap<Vec<u8>, Vec<EventualityFor<S>>> {
    // Find the key to filfill these payments with
    let fulfillment_key = match active_keys[0].1 {
      LifetimeStage::ActiveYetNotReporting => {
        panic!("expected to fulfill payments despite not reporting for the oldest key")
      }
      LifetimeStage::Active | LifetimeStage::UsingNewForChange => active_keys[0].0,
      LifetimeStage::Forwarding | LifetimeStage::Finishing => active_keys[1].0,
    };

    // Queue the payments for this key
    for coin in S::NETWORK.coins() {
      let mut queued_payments = Db::<S>::queued_payments(txn, fulfillment_key, *coin).unwrap();
      queued_payments
        .extend(payments.iter().filter(|payment| payment.balance().coin == *coin).cloned());
      Db::<S>::set_queued_payments(txn, fulfillment_key, *coin, &queued_payments);
    }

    // Handle the queued payments
    HashMap::from([(
      fulfillment_key.to_bytes().as_ref().to_vec(),
      self.handle_queued_payments(txn, active_keys, fulfillment_key),
    )])
  }
}
