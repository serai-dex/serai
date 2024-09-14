#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{marker::PhantomData, future::Future};
use std::collections::HashMap;

use group::GroupEncoding;

use serai_primitives::{Coin, Amount};

use serai_db::DbTxn;

use primitives::{OutputType, ReceivedOutput, Payment};
use scanner::{
  LifetimeStage, ScannerFeed, KeyFor, AddressFor, OutputFor, EventualityFor, BlockFor,
  SchedulerUpdate, KeyScopedEventualities, Scheduler as SchedulerTrait,
};
use scheduler_primitives::*;
use utxo_scheduler_primitives::*;

mod db;
use db::Db;

/// The outputs which will be effected by a PlannedTransaction and received by Serai.
pub struct EffectedReceivedOutputs<S: ScannerFeed>(pub Vec<OutputFor<S>>);

/// A scheduler of transactions for networks premised on the UTXO model which support
/// transaction chaining.
#[allow(non_snake_case)]
#[derive(Clone)]
pub struct Scheduler<S: ScannerFeed, P: TransactionPlanner<S, EffectedReceivedOutputs<S>>> {
  planner: P,
  _S: PhantomData<S>,
}

impl<S: ScannerFeed, P: TransactionPlanner<S, EffectedReceivedOutputs<S>>> Scheduler<S, P> {
  /// Create a new scheduler.
  pub fn new(planner: P) -> Self {
    Self { planner, _S: PhantomData }
  }

  fn accumulate_outputs(txn: &mut impl DbTxn, outputs: Vec<OutputFor<S>>, from_scanner: bool) {
    let mut outputs_by_key = HashMap::new();
    for output in outputs {
      if !from_scanner {
        // Since this isn't being reported by the scanner, flag it so when the scanner does report
        // it, we don't accumulate it again
        Db::<S>::set_already_accumulated_output(txn, &output.id());
      } else if Db::<S>::take_if_already_accumulated_output(txn, &output.id()) {
        continue;
      }

      let coin = output.balance().coin;
      outputs_by_key
        // Index by key and coin
        .entry((output.key().to_bytes().as_ref().to_vec(), coin))
        // If we haven't accumulated here prior, read the outputs from the database
        .or_insert_with(|| (output.key(), Db::<S>::outputs(txn, output.key(), coin).unwrap()))
        .1
        .push(output);
    }
    // Write the outputs back to the database
    for ((_key_vec, coin), (key, outputs)) in outputs_by_key {
      Db::<S>::set_outputs(txn, key, coin, &outputs);
    }
  }

  async fn aggregate_inputs(
    &self,
    txn: &mut impl DbTxn,
    block: &BlockFor<S>,
    key_for_change: KeyFor<S>,
    key: KeyFor<S>,
    coin: Coin,
  ) -> Result<Vec<EventualityFor<S>>, <Self as SchedulerTrait<S>>::EphemeralError> {
    let mut eventualities = vec![];

    let mut operating_costs = Db::<S>::operating_costs(txn, coin).0;
    let mut outputs = Db::<S>::outputs(txn, key, coin).unwrap();
    while outputs.len() > P::MAX_INPUTS {
      let to_aggregate = outputs.drain(.. P::MAX_INPUTS).collect::<Vec<_>>();
      Db::<S>::set_outputs(txn, key, coin, &outputs);

      let Some(planned) = self
        .planner
        .plan_transaction_with_fee_amortization(
          &mut operating_costs,
          block,
          to_aggregate,
          vec![],
          Some(key_for_change),
        )
        .await?
      else {
        continue;
      };

      TransactionsToSign::<P::SignableTransaction>::send(txn, &key, &planned.signable);
      eventualities.push(planned.eventuality);
      Self::accumulate_outputs(txn, planned.auxilliary.0, false);

      // Reload the outputs for the next loop iteration
      outputs = Db::<S>::outputs(txn, key, coin).unwrap();
    }

    Db::<S>::set_operating_costs(txn, coin, Amount(operating_costs));
    Ok(eventualities)
  }

  fn fulfillable_payments(
    txn: &mut impl DbTxn,
    operating_costs: &mut u64,
    key: KeyFor<S>,
    coin: Coin,
    value_of_outputs: u64,
  ) -> Vec<Payment<AddressFor<S>>> {
    // Fetch all payments for this key
    let mut payments = Db::<S>::queued_payments(txn, key, coin).unwrap();
    if payments.is_empty() {
      return vec![];
    }

    loop {
      // inputs must be >= (payments - operating costs)
      // Accordingly, (inputs + operating costs) must be >= payments
      let value_fulfillable = value_of_outputs + *operating_costs;

      // Drop to just the payments we can currently fulfill
      {
        let mut can_handle = 0;
        let mut value_used = 0;
        for payment in &payments {
          value_used += payment.balance().amount.0;
          if value_fulfillable < value_used {
            break;
          }
          can_handle += 1;
        }

        let remaining_payments = payments.drain(can_handle ..).collect::<Vec<_>>();
        // Restore the rest to the database
        Db::<S>::set_queued_payments(txn, key, coin, &remaining_payments);
      }

      // If these payments are worth less than the operating costs, immediately drop them
      let payments_value = payments.iter().map(|payment| payment.balance().amount.0).sum::<u64>();
      if payments_value <= *operating_costs {
        *operating_costs -= payments_value;
        Db::<S>::set_operating_costs(txn, coin, Amount(*operating_costs));

        // Reset payments to the queued payments
        payments = Db::<S>::queued_payments(txn, key, coin).unwrap();
        // If there's no more payments, stop looking for which payments we should fulfill
        if payments.is_empty() {
          return vec![];
        }
        // Find which of these we should handle
        continue;
      }

      return payments;
    }
  }

  async fn step(
    &self,
    txn: &mut impl DbTxn,
    active_keys: &[(KeyFor<S>, LifetimeStage)],
    block: &BlockFor<S>,
    key: KeyFor<S>,
  ) -> Result<Vec<EventualityFor<S>>, <Self as SchedulerTrait<S>>::EphemeralError> {
    let mut eventualities = vec![];

    let key_for_change = match active_keys[0].1 {
      LifetimeStage::ActiveYetNotReporting => {
        panic!("expected to fulfill payments despite not reporting for the oldest key")
      }
      LifetimeStage::Active => active_keys[0].0,
      LifetimeStage::UsingNewForChange | LifetimeStage::Forwarding | LifetimeStage::Finishing => {
        active_keys[1].0
      }
    };
    let branch_address = P::branch_address(key);

    'coin: for coin in S::NETWORK.coins() {
      let coin = *coin;

      // Perform any input aggregation we should
      eventualities
        .append(&mut self.aggregate_inputs(txn, block, key_for_change, key, coin).await?);

      // Fetch the operating costs/outputs
      let mut operating_costs = Db::<S>::operating_costs(txn, coin).0;
      let outputs = Db::<S>::outputs(txn, key, coin).unwrap();
      if outputs.is_empty() {
        continue;
      }

      // Fetch the fulfillable payments
      let payments = Self::fulfillable_payments(
        txn,
        &mut operating_costs,
        key,
        coin,
        outputs.iter().map(|output| output.balance().amount.0).sum(),
      );
      if payments.is_empty() {
        continue;
      }

      // If this is our only key, we should be able to fulfill all payments
      // Else, we'd be insolvent
      if active_keys.len() == 1 {
        assert!(Db::<S>::queued_payments(txn, key, coin).unwrap().is_empty());
      }

      // Create a tree to fulfill the payments
      let mut tree = vec![P::tree(&payments)];

      // Create the transaction for the root of the tree
      let mut branch_outputs = {
        // Try creating this transaction twice, once with a change output and once with increased
        // operating costs to ensure a change output (as necessary to meet the requirements of the
        // scanner API)
        let mut planned_outer = None;
        for i in 0 .. 2 {
          let Some(planned) = self
            .planner
            .plan_transaction_with_fee_amortization(
              &mut operating_costs,
              block,
              outputs.clone(),
              tree[0]
                .payments::<S>(coin, &branch_address, tree[0].value())
                .expect("payments were dropped despite providing an input of the needed value"),
              Some(key_for_change),
            )
            .await?
          else {
            // This should trip on the first iteration or not at all
            assert_eq!(i, 0);
            // This doesn't have inputs even worth aggregating so drop the entire tree
            Db::<S>::set_operating_costs(txn, coin, Amount(operating_costs));
            continue 'coin;
          };

          // If this doesn't have a change output, increase operating costs and try again
          if !planned.has_change {
            /*
              Since we'll create a change output if it's worth at least dust, amortizing dust from
              the payments should solve this. If the new transaction can't afford those operating
              costs, then the payments should be amortized out, causing there to be a change or no
              transaction at all.
            */
            operating_costs += S::dust(coin).0;
            continue;
          }

          // Since this had a change output, move forward with it
          planned_outer = Some(planned);
          break;
        }
        let Some(mut planned) = planned_outer else {
          panic!("couldn't create a tree root with a change output")
        };
        Db::<S>::set_operating_costs(txn, coin, Amount(operating_costs));
        TransactionsToSign::<P::SignableTransaction>::send(txn, &key, &planned.signable);
        eventualities.push(planned.eventuality);

        // We accumulate the change output, but not the branches as we'll consume them momentarily
        Self::accumulate_outputs(
          txn,
          planned
            .auxilliary
            .0
            .iter()
            .filter(|output| output.kind() == OutputType::Change)
            .cloned()
            .collect(),
          false,
        );
        planned.auxilliary.0.retain(|output| output.kind() == OutputType::Branch);
        planned.auxilliary.0
      };

      // Now execute each layer of the tree
      tree = match tree.remove(0) {
        TreeTransaction::Leaves { .. } => vec![],
        TreeTransaction::Branch { children, .. } => children,
      };
      while !tree.is_empty() {
        // Sort the branch outputs by their value (high to low)
        branch_outputs.sort_by_key(|a| a.balance().amount.0);
        branch_outputs.reverse();
        // Sort the transactions we should create by their value so they share an order with the
        // branch outputs
        tree.sort_by_key(TreeTransaction::value);
        tree.reverse();

        // If we dropped any Branch outputs, drop the associated children
        tree.truncate(branch_outputs.len());
        assert_eq!(branch_outputs.len(), tree.len());

        let branch_outputs_for_this_layer = branch_outputs;
        let this_layer = tree;
        branch_outputs = vec![];
        tree = vec![];

        for (branch_output, tx) in branch_outputs_for_this_layer.into_iter().zip(this_layer) {
          assert_eq!(branch_output.kind(), OutputType::Branch);

          let Some(payments) =
            tx.payments::<S>(coin, &branch_address, branch_output.balance().amount.0)
          else {
            // If this output has become too small to satisfy this branch, drop it
            continue;
          };

          let branch_output_id = branch_output.id();
          let Some(mut planned) = self
            .planner
            .plan_transaction_with_fee_amortization(
              // Uses 0 as there's no operating costs to incur/amortize here
              &mut 0,
              block,
              vec![branch_output],
              payments,
              None,
            )
            .await?
          else {
            // This Branch isn't viable, so drop it (and its children)
            continue;
          };
          // Since we've made a TX spending this output, don't accumulate it later
          Db::<S>::set_already_accumulated_output(txn, &branch_output_id);
          TransactionsToSign::<P::SignableTransaction>::send(txn, &key, &planned.signable);
          eventualities.push(planned.eventuality);

          match tx {
            TreeTransaction::Leaves { .. } => {}
            // If this was a branch, handle its children
            TreeTransaction::Branch { mut children, .. } => {
              branch_outputs.append(&mut planned.auxilliary.0);
              tree.append(&mut children);
            }
          }
        }
      }
    }

    Ok(eventualities)
  }

  async fn flush_outputs(
    &self,
    txn: &mut impl DbTxn,
    eventualities: &mut KeyScopedEventualities<S>,
    block: &BlockFor<S>,
    from: KeyFor<S>,
    to: KeyFor<S>,
    coin: Coin,
  ) -> Result<(), <Self as SchedulerTrait<S>>::EphemeralError> {
    let from_bytes = from.to_bytes().as_ref().to_vec();
    // Ensure our inputs are aggregated
    eventualities
      .entry(from_bytes.clone())
      .or_insert(vec![])
      .append(&mut self.aggregate_inputs(txn, block, to, from, coin).await?);

    // Now that our inputs are aggregated, transfer all of them to the new key
    let mut operating_costs = Db::<S>::operating_costs(txn, coin).0;
    let outputs = Db::<S>::outputs(txn, from, coin).unwrap();
    if outputs.is_empty() {
      return Ok(());
    }
    let planned = self
      .planner
      .plan_transaction_with_fee_amortization(
        &mut operating_costs,
        block,
        outputs,
        vec![],
        Some(to),
      )
      .await?;
    Db::<S>::set_operating_costs(txn, coin, Amount(operating_costs));
    let Some(planned) = planned else { return Ok(()) };

    TransactionsToSign::<P::SignableTransaction>::send(txn, &from, &planned.signable);
    eventualities.get_mut(&from_bytes).unwrap().push(planned.eventuality);
    Self::accumulate_outputs(txn, planned.auxilliary.0, false);

    Ok(())
  }
}

impl<S: ScannerFeed, P: TransactionPlanner<S, EffectedReceivedOutputs<S>>> SchedulerTrait<S>
  for Scheduler<S, P>
{
  type EphemeralError = P::EphemeralError;
  type SignableTransaction = P::SignableTransaction;

  fn activate_key(txn: &mut impl DbTxn, key: KeyFor<S>) {
    for coin in S::NETWORK.coins() {
      assert!(Db::<S>::outputs(txn, key, *coin).is_none());
      Db::<S>::set_outputs(txn, key, *coin, &[]);
      assert!(Db::<S>::queued_payments(txn, key, *coin).is_none());
      Db::<S>::set_queued_payments(txn, key, *coin, &[]);
    }
  }

  fn flush_key(
    &self,
    txn: &mut impl DbTxn,
    block: &BlockFor<S>,
    retiring_key: KeyFor<S>,
    new_key: KeyFor<S>,
  ) -> impl Send + Future<Output = Result<KeyScopedEventualities<S>, Self::EphemeralError>> {
    async move {
      let mut eventualities = HashMap::new();
      for coin in S::NETWORK.coins() {
        // Move the payments to the new key
        {
          let still_queued = Db::<S>::queued_payments(txn, retiring_key, *coin).unwrap();
          let mut new_queued = Db::<S>::queued_payments(txn, new_key, *coin).unwrap();

          let mut queued = still_queued;
          queued.append(&mut new_queued);

          Db::<S>::set_queued_payments(txn, retiring_key, *coin, &[]);
          Db::<S>::set_queued_payments(txn, new_key, *coin, &queued);
        }

        // Move the outputs to the new key
        self.flush_outputs(txn, &mut eventualities, block, retiring_key, new_key, *coin).await?;
      }
      Ok(eventualities)
    }
  }

  fn retire_key(txn: &mut impl DbTxn, key: KeyFor<S>) {
    for coin in S::NETWORK.coins() {
      assert!(Db::<S>::outputs(txn, key, *coin).unwrap().is_empty());
      Db::<S>::del_outputs(txn, key, *coin);
      assert!(Db::<S>::queued_payments(txn, key, *coin).unwrap().is_empty());
      Db::<S>::del_queued_payments(txn, key, *coin);
    }
  }

  fn update(
    &self,
    txn: &mut impl DbTxn,
    block: &BlockFor<S>,
    active_keys: &[(KeyFor<S>, LifetimeStage)],
    update: SchedulerUpdate<S>,
  ) -> impl Send + Future<Output = Result<KeyScopedEventualities<S>, Self::EphemeralError>> {
    async move {
      Self::accumulate_outputs(txn, update.outputs().to_vec(), true);

      // Fulfill the payments we prior couldn't
      let mut eventualities = HashMap::new();
      for (key, _stage) in active_keys {
        assert!(eventualities
          .insert(key.to_bytes().as_ref().to_vec(), self.step(txn, active_keys, block, *key).await?)
          .is_none());
      }

      // If this key has been flushed, forward all outputs
      match active_keys[0].1 {
        LifetimeStage::ActiveYetNotReporting |
        LifetimeStage::Active |
        LifetimeStage::UsingNewForChange => {}
        LifetimeStage::Forwarding | LifetimeStage::Finishing => {
          for coin in S::NETWORK.coins() {
            self
              .flush_outputs(
                txn,
                &mut eventualities,
                block,
                active_keys[0].0,
                active_keys[1].0,
                *coin,
              )
              .await?;
          }
        }
      }

      // Create the transactions for the forwards/returns
      {
        let mut planned_txs = vec![];
        for forward in update.forwards() {
          let key = forward.key();

          assert_eq!(active_keys.len(), 2);
          assert_eq!(active_keys[0].1, LifetimeStage::Forwarding);
          assert_eq!(active_keys[1].1, LifetimeStage::Active);
          let forward_to_key = active_keys[1].0;

          let Some(plan) = self
            .planner
            .plan_transaction_with_fee_amortization(
              // This uses 0 for the operating costs as we don't incur any here
              // If the output can't pay for itself to be forwarded, we simply drop it
              &mut 0,
              block,
              vec![forward.clone()],
              vec![Payment::new(P::forwarding_address(forward_to_key), forward.balance(), None)],
              None,
            )
            .await?
          else {
            continue;
          };
          planned_txs.push((key, plan));
        }
        for to_return in update.returns() {
          let key = to_return.output().key();
          let out_instruction =
            Payment::new(to_return.address().clone(), to_return.output().balance(), None);
          let Some(plan) = self
            .planner
            .plan_transaction_with_fee_amortization(
              // This uses 0 for the operating costs as we don't incur any here
              // If the output can't pay for itself to be returned, we simply drop it
              &mut 0,
              block,
              vec![to_return.output().clone()],
              vec![out_instruction],
              None,
            )
            .await?
          else {
            continue;
          };
          planned_txs.push((key, plan));
        }

        for (key, planned_tx) in planned_txs {
          // Send the transactions off for signing
          TransactionsToSign::<P::SignableTransaction>::send(txn, &key, &planned_tx.signable);

          // Insert the Eventualities into the result
          eventualities.get_mut(key.to_bytes().as_ref()).unwrap().push(planned_tx.eventuality);
        }

        Ok(eventualities)
      }
    }
  }

  fn fulfill(
    &self,
    txn: &mut impl DbTxn,
    block: &BlockFor<S>,
    active_keys: &[(KeyFor<S>, LifetimeStage)],
    payments: Vec<Payment<AddressFor<S>>>,
  ) -> impl Send + Future<Output = Result<KeyScopedEventualities<S>, Self::EphemeralError>> {
    async move {
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
      Ok(HashMap::from([(
        fulfillment_key.to_bytes().as_ref().to_vec(),
        self.step(txn, active_keys, block, fulfillment_key).await?,
      )]))
    }
  }
}
