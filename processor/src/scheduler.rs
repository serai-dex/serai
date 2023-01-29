use std::collections::{VecDeque, HashMap};

use crate::coin::{Output, Coin};

#[derive(Clone, PartialEq, Eq, Debug)]
struct Payment<C: Coin> {
  address: C::Address,
  amount: u64,
}

// Stores a flattened map of amounts to payments.
// These amounts are known to be upcoming and when they do show up, the included payments should be
// continued
// TODO: Consider edge case where branch/change isn't mined yet keys are deprecated
// Continuing them means creating the next set of branches necessary, or leaves as possible
// The Vec<Payment> is for all payments that should be done for an output instance
// The VecDeque allows multiple sets of payments mutually dependent on an output worth a specific
// amount to co-exist and be properly handled
pub struct Scheduler<C: Coin>(HashMap<u64, VecDeque<Vec<Payment<C>>>>);

impl<C: Coin> Scheduler<C> {
  fn new() -> Self {
    Scheduler(HashMap::new())
  }

  // Schedule a series of payments
  fn schedule(&mut self, utxos: &mut Vec<C::Output>, payments: Vec<Payment<C>>) {
    todo!();
  }

  // Having received an output, check if it's usable for continuing any planned payments
  // While this could limit itself to outputs intended to be used as branches, there's no practical
  // value to doing so
  fn attempt_plan(&mut self, output: C::Output) {
    // If there's no plans for an output of this amount, return
    if !self.0.contains_key(&output.amount()) {
      return;
    }

    // Execute the first set of payments possible with an output of this amount
    let payments = self.0.get_mut(&output.amount()).unwrap().pop_front().unwrap();
    debug_assert_eq!(output.amount(), payments.iter().map(|payment| payment.amount).sum::<u64>());

    // If there's more outputs than we can fit in a TX, create and write-back branches
    // TODO
  }
}

impl<C: Coin> Default for Scheduler<C> {
  fn default() -> Self {
    Scheduler::new()
  }
}
