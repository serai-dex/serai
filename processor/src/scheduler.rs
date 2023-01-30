use std::collections::{VecDeque, HashMap};

use frost::curve::Ciphersuite;

use crate::coin::{Output, Coin};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Payment<C: Coin> {
  address: C::Address,
  amount: u64,
}

/// Stateless, deterministic output/payment manager.
#[derive(Debug)]
pub struct Scheduler<C: Coin> {
  key: <C::Curve as Ciphersuite>::G,

  // Flattened map of amounts to payments.
  // These amounts are known to be upcoming and when they do show up, the included payments should
  // be continued
  // TODO: Consider edge case where branch/change isn't mined yet keys are deprecated
  // Continuing them means creating the next set of branches necessary, or leaves as possible
  // The Vec<Payment> is for all payments that should be done for an output instance
  // The VecDeque allows multiple sets of payments mutually dependent on an output worth a specific
  // amount to co-exist and be properly handled
  plans: HashMap<u64, VecDeque<Vec<Payment<C>>>>,

  // UTXOs available
  utxos: Vec<C::Output>,

  // Payments awaiting scheduling due to the output availability problem
  payments: VecDeque<Payment<C>>,
}

#[derive(Clone, Debug)]
pub struct Transaction<C: Coin> {
  inputs: Vec<C::Output>,
  payments: Vec<Payment<C>>,
  change: bool,
}

impl<C: Coin> Scheduler<C> {
  pub fn new(key: <C::Curve as Ciphersuite>::G) -> Self {
    Scheduler { key, plans: HashMap::new(), utxos: vec![], payments: VecDeque::new() }
  }

  fn execute(&mut self, inputs: Vec<C::Output>, mut payments: Vec<Payment<C>>) -> Transaction<C> {
    let mut change = false;
    let mut max = C::MAX_OUTPUTS;

    let payment_amounts =
      |payments: &Vec<Payment<C>>| payments.iter().map(|payment| payment.amount).sum::<u64>();

    // Requires a change output
    if inputs.iter().map(Output::amount).sum::<u64>() != payment_amounts(&payments) {
      change = true;
      max -= 1;
    }

    let mut add_plan = |payments| {
      let amount = payment_amounts(&payments);
      self.plans.entry(amount).or_insert(VecDeque::new()).push_back(payments);
      amount
    };

    // If we have more payments than we can handle in a single TX, create plans for them
    // TODO: This isn't perfect. For 258 outputs, and a MAX_OUTPUTS of 16, this will create:
    // 15 branches of 16 leaves
    // 1 branch of:
    // - 1 branch of 16 leaves
    // - 2 leaves
    // If this was perfect, the heaviest branch would have 1 branch of 3 leaves and 15 leaves
    while payments.len() > max {
      // The resulting TX will have the remaining payments and a new branch payment
      let to_remove = (payments.len() + 1) - C::MAX_OUTPUTS;
      // Don't remove more than possible
      let to_remove = to_remove.min(C::MAX_OUTPUTS);

      // Create the plan
      let removed = payments.drain((payments.len() - to_remove) ..).collect::<Vec<_>>();
      debug_assert_eq!(removed.len(), to_remove);
      let amount = add_plan(removed);

      // Create the payment for the plan
      // Push it to the front so it's not moved into a branch until all lower-depth items are
      payments.insert(0, Payment { address: C::branch_address(self.key), amount });
    }

    Transaction { inputs, payments, change }
  }

  // When Substrate emits `Updates` for a coin, all outputs should be added up to the
  // acknowledged block.
  pub fn add_outputs(&mut self, mut utxos: Vec<C::Output>) -> Vec<Transaction<C>> {
    let mut txs = vec![];

    for utxo in utxos.drain(..) {
      // If we can fulfill planned TXs with this output, do so
      // We could limit this to UTXOs where `utxo.kind() == OutputType::Branch`, yet there's no
      // practical benefit in doing so
      if let Some(plans) = self.plans.get_mut(&utxo.amount()) {
        // Execute the first set of payments possible with an output of this amount
        let payments = plans.pop_front().unwrap();
        debug_assert_eq!(utxo.amount(), payments.iter().map(|payment| payment.amount).sum::<u64>());

        // If we've grabbedthe last plan for this output amount, remove it from the map
        if plans.is_empty() {
          self.plans.remove(&utxo.amount());
        }

        // Create a TX for these payments
        // TODO: Subsidize the TX fee across all included payments.
        txs.push(self.execute(vec![utxo], payments));
      } else {
        self.utxos.push(utxo);
      }
    }

    // Sort the UTXOs by amount
    utxos.sort_by(|a, b| a.amount().cmp(&b.amount()).reverse());

    // Return the now possible TXs
    txs
  }

  // Schedule a series of payments. This should be called after `add_outputs`.
  pub fn schedule(&mut self, mut payments: Vec<Payment<C>>) -> Vec<Transaction<C>> {
    debug_assert!(!payments.is_empty(), "tried to schedule zero payments");

    // Add all new payments to the list of pending payments
    self.payments.extend(payments.drain(..));
    // Drop payments to descope the variable
    drop(payments);

    // If we don't have UTXOs available, don't try to continue
    if self.utxos.is_empty() {
      return vec![];
    }

    // We always want to aggregate our UTXOs into a single UTXO in the name of simplicity
    // We may have more UTXOs than will fit into a TX though
    // We use the most valuable UTXOs to handle our current payments, and we return aggregation TXs
    // for the rest of the inputs
    // Since we do multiple aggregation TXs at once, this will execute in logarithmic time
    let utxos = self.utxos.drain(..).collect::<Vec<_>>();
    let mut utxo_chunks =
      utxos.chunks(C::MAX_INPUTS).map(|chunk| chunk.to_vec()).collect::<Vec<_>>();
    let utxos = utxo_chunks.remove(0);

    // If the last chunk exists and only has one output, don't try aggregating it
    // Just immediately consider it another output
    if let Some(mut chunk) = utxo_chunks.pop() {
      if chunk.len() == 1 {
        self.utxos.push(chunk.pop().unwrap());
      } else {
        utxo_chunks.push(chunk);
      }
    }

    let mut aggregating = vec![];
    for chunk in utxo_chunks.drain(..) {
      aggregating.push(Transaction { inputs: chunk, payments: vec![], change: true })
    }

    // We want to use all possible UTXOs for all possible payments
    let mut balance = utxos.iter().map(Output::amount).sum::<u64>();

    // If we can't fulfill the next payment, we have encountered an instance of the UTXO
    // availability problem
    // This shows up in coins like Monero, where because we spent outputs, our change has yet to
    // re-appear. Since it has yet to re-appear, we only operate with a balance which is a subset
    // of our total balance
    // Despite this, we may be order to fulfill a payment which is our total balance
    // The solution is to wait for the temporarily unavailable change outputs to re-appear,
    // granting us access to our full balance
    let mut executing = vec![];
    while !self.payments.is_empty() {
      let amount = self.payments[0].amount;
      if balance.checked_sub(amount).is_some() {
        balance -= amount;
        executing.push(self.payments.pop_front().unwrap());
      }
    }

    // Now that we have the list of payments we can successfully handle right now, create the TX
    // for them
    let mut txs = vec![self.execute(utxos, executing)];
    txs.append(&mut aggregating);
    txs
  }
}
