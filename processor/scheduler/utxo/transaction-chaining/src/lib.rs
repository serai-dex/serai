#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::marker::PhantomData;
use std::collections::HashMap;

use group::GroupEncoding;

use serai_primitives::{Coin, Amount};

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

    for coin in S::NETWORK.coins() {
      // Fetch our operating costs and all our outputs
      let mut operating_costs = Db::<S>::operating_costs(txn, *coin).0;
      let mut outputs = Db::<S>::outputs(txn, key, *coin).unwrap();

      // Fetch the queued payments
      let mut payments = Db::<S>::queued_payments(txn, key, *coin).unwrap();
      if payments.is_empty() {
        continue;
      }

      // If this is our only key, our outputs and operating costs should be greater than the
      // payments' value
      if active_keys.len() == 1 {
        // The available amount of fulfill is the amount we have plus the amount we'll reduce by
        // An alternative formulation would be `outputs >= (payments - operating costs)`, but
        // that'd risk underflow
        let available =
          operating_costs + outputs.iter().map(|output| output.balance().amount.0).sum::<u64>();
        assert!(
          available >= payments.iter().map(|payment| payment.balance().amount.0).sum::<u64>()
        );
      }

      let amount_of_payments_that_can_be_handled =
        |operating_costs: u64, outputs: &[_], payments: &[_]| {
          let value_available =
            operating_costs + outputs.iter().map(|output| output.balance().amount.0).sum::<u64>();

          let mut can_handle = 0;
          let mut value_used = 0;
          for payment in payments {
            value_used += payment.balance().amount.0;
            if value_available < value_used {
              break;
            }
            can_handle += 1;
          }

          can_handle
        };

      // Find the set of payments we should fulfill at this time
      {
        // Drop to just the payments we currently have the outputs for
        {
          let can_handle =
            amount_of_payments_that_can_be_handled(operating_costs, &outputs, &payments);
          let remaining_payments = payments.drain(can_handle ..).collect::<Vec<_>>();
          // Restore the rest to the database
          Db::<S>::set_queued_payments(txn, key, *coin, &remaining_payments);
        }
        let payments_value = payments.iter().map(|payment| payment.balance().amount.0).sum::<u64>();

        // If these payments are worth less than the operating costs, immediately drop them
        if payments_value <= operating_costs {
          operating_costs -= payments_value;
          Db::<S>::set_operating_costs(txn, *coin, Amount(operating_costs));
          return vec![];
        }

        // We explicitly sort AFTER deciding which payments to handle so we always handle the
        // oldest queued payments first (preventing any from eternally being shuffled to the back
        // of the line)
        payments.sort_by(|a, b| a.balance().amount.0.cmp(&b.balance().amount.0));
      }
      assert!(!payments.is_empty());

      // Find the smallest set of outputs usable to fulfill these outputs
      // Size is determined by the largest output, not quantity nor aggregate value
      {
        // We start by sorting low to high
        outputs.sort_by(|a, b| a.balance().amount.0.cmp(&b.balance().amount.0));

        let value_needed =
          payments.iter().map(|payment| payment.balance().amount.0).sum::<u64>() - operating_costs;

        let mut needed = 0;
        let mut value_present = 0;
        for output in &outputs {
          needed += 1;
          value_present += output.balance().amount.0;
          if value_present >= value_needed {
            break;
          }
        }

        // Drain, and save back to the DB, the unnecessary outputs
        let remaining_outputs = outputs.drain(needed ..).collect::<Vec<_>>();
        Db::<S>::set_outputs(txn, key, *coin, &remaining_outputs);
      }
      assert!(!outputs.is_empty());

      // We now have the current operating costs, the outputs we're using, and the payments
      // The database has the unused outputs/unfilfillable payments
      // Actually plan/send off the transactions

      // While our set of outputs exceed the input limit, aggregate them
      while outputs.len() > MAX_INPUTS {
        let outputs_chunk = outputs.drain(.. MAX_INPUTS).collect::<Vec<_>>();

        // While we're aggregating these outputs, handle any payments we can
        let payments_chunk = loop {
          let can_handle =
            amount_of_payments_that_can_be_handled(operating_costs, &outputs, &payments);
          let payments_chunk = payments.drain(.. can_handle.min(MAX_OUTPUTS)).collect::<Vec<_>>();

          let payments_value =
            payments_chunk.iter().map(|payment| payment.balance().amount.0).sum::<u64>();
          if payments_value <= operating_costs {
            operating_costs -= payments_value;
            continue;
          }
          break payments_chunk;
        };

        let Some(planned) = P::plan_transaction_with_fee_amortization(
          &mut operating_costs,
          fee_rates[coin],
          outputs_chunk,
          payments_chunk,
          // We always use our key for the change here since we may need this change output to
          // finish fulfilling these payments
          Some(key),
        ) else {
          // We amortized all payments, and even when just trying to make the change output, these
          // inputs couldn't afford their own aggregation and were written off
          continue;
        };

        // Send the transactions off for signing
        TransactionsToSign::<P::SignableTransaction>::send(txn, &key, &planned.signable);

        // Push the Eventualities onto the result
        eventualities.push(planned.eventuality);

        let mut effected_received_outputs = planned.auxilliary.0;
        // Only handle Change so if someone burns to an External address, we don't use it here
        // when the scanner will tell us to return it (without accumulating it)
        effected_received_outputs.retain(|output| output.kind() == OutputType::Change);
        for output in &effected_received_outputs {
          Db::<S>::set_already_accumulated_output(txn, output.id());
        }
        outputs.append(&mut effected_received_outputs);
      }

      // Now that we have an aggregated set of inputs, create the tree for payments
      todo!("TODO");
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
