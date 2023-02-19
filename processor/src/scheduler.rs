use std::collections::{VecDeque, HashMap};

use frost::curve::Ciphersuite;

use crate::{
  coins::{Output, Coin},
  Payment, Plan,
};

/// Stateless, deterministic output/payment manager.
#[derive(Debug)]
pub struct Scheduler<C: Coin> {
  key: <C::Curve as Ciphersuite>::G,

  // Serai, when it has more outputs expected than it can handle in a single tranaction, will
  // schedule the outputs to be handled later. Immediately, it just creates additional outputs
  // which will eventually handle those outputs
  //
  // These maps map output amounts, which we'll receive in the future, to the payments they should
  // be used on
  //
  // When those output amounts appear, their payments should be scheduled
  // The Vec<Payment> is for all payments that should be done per output instance
  // The VecDeque allows multiple sets of payments with the same sum amount to properly co-exist
  //
  // queued_plans are for outputs which we will create, yet when created, will have their amount
  // reduced by the fee it cost to be created. The Scheduler will then be told how what amount the
  // output actually has, and it'll be moved into plans
  //
  // TODO: Consider edge case where branch/change isn't mined yet keys are deprecated
  queued_plans: HashMap<u64, VecDeque<Vec<Payment<C>>>>,
  plans: HashMap<u64, VecDeque<Vec<Payment<C>>>>,

  // UTXOs available
  utxos: Vec<C::Output>,

  // Payments awaiting scheduling due to the output availability problem
  payments: VecDeque<Payment<C>>,
}

impl<C: Coin> Scheduler<C> {
  pub fn new(key: <C::Curve as Ciphersuite>::G) -> Self {
    Scheduler {
      key,
      queued_plans: HashMap::new(),
      plans: HashMap::new(),
      utxos: vec![],
      payments: VecDeque::new(),
    }
  }

  fn execute(&mut self, inputs: Vec<C::Output>, mut payments: Vec<Payment<C>>) -> Plan<C> {
    let branch_address = C::branch_address(self.key);
    // created_output will be called any time we send to a branch address
    // If it's called, and it wasn't expecting to be called, that's almost certainly an error
    // The only way it wouldn't be is if someone on Serai triggered a burn to a branch, which is
    // pointless anyways
    // If we allow such behavior, we lose the ability to detect the aforementioned class of errors
    // Ignore these payments so we can safely assert there
    let mut payments =
      payments.drain(..).filter(|payment| payment.address != branch_address).collect::<Vec<_>>();

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
      self.queued_plans.entry(amount).or_insert(VecDeque::new()).push_back(payments);
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
      assert_eq!(removed.len(), to_remove);
      let amount = add_plan(removed);

      // Create the payment for the plan
      // Push it to the front so it's not moved into a branch until all lower-depth items are
      payments.insert(0, Payment { address: branch_address.clone(), data: None, amount });
    }

    // TODO: Use the latest key for change
    // TODO: Update rotation documentation
    Plan { key: self.key, inputs, payments, change: Some(self.key).filter(|_| change) }
  }

  // When Substrate emits `Updates` for a coin, all outputs should be added up to the
  // acknowledged block.
  pub fn add_outputs(&mut self, mut utxos: Vec<C::Output>) -> Vec<Plan<C>> {
    let mut txs = vec![];

    for utxo in utxos.drain(..) {
      // If we can fulfill planned TXs with this output, do so
      // We could limit this to UTXOs where `utxo.kind() == OutputType::Branch`, yet there's no
      // practical benefit in doing so
      if let Some(plans) = self.plans.get_mut(&utxo.amount()) {
        // Execute the first set of payments possible with an output of this amount
        let payments = plans.pop_front().unwrap();
        // They won't be equal if we dropped payments due to being dust
        assert!(utxo.amount() >= payments.iter().map(|payment| payment.amount).sum::<u64>());

        // If we've grabbed the last plan for this output amount, remove it from the map
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
    log::info!("created {} planned TXs to sign from now recived outputs", txs.len());
    txs
  }

  // Schedule a series of payments. This should be called after `add_outputs`.
  pub fn schedule(&mut self, payments: Vec<Payment<C>>) -> Vec<Plan<C>> {
    log::debug!("scheduling payments");
    assert!(!payments.is_empty(), "tried to schedule zero payments");

    // Add all new payments to the list of pending payments
    self.payments.extend(payments);

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
      aggregating.push(Plan {
        key: self.key,
        inputs: chunk,
        payments: vec![],
        change: Some(self.key),
      })
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
    log::info!("created {} TXs to sign", txs.len());
    txs
  }

  // Note a branch output as having been created, with the amount it was actually created with,
  // or not having been created due to being too small
  // This can be called whenever, so long as it's properly ordered
  // (it's independent to Serai/the chain we're scheduling over, yet still expects outputs to be
  // created in the same order Plans are returned in)
  pub fn created_output(&mut self, expected: u64, actual: Option<u64>) {
    log::debug!("output expected to have {} had {:?} after fees", expected, actual);

    // Get the payments this output is expected to handle
    let queued = self.queued_plans.get_mut(&expected).unwrap();
    let mut payments = queued.pop_front().unwrap();
    assert_eq!(expected, payments.iter().map(|payment| payment.amount).sum::<u64>());
    // If this was the last set of payments at this amount, remove it
    if queued.is_empty() {
      self.queued_plans.remove(&expected);
    }

    // If we didn't actually create this output, return, dropping the child payments
    let actual = match actual {
      Some(actual) => actual,
      None => return,
    };

    // Amortize the fee amongst all payments
    // While some coins, like Ethereum, may have some payments take notably more gas, those payments
    // will have their own gas deducted when they're created. The difference in output value present
    // here is solely the cost of the branch, which is used for all of these payments, regardless of
    // how much they'll end up costing
    let diff = actual - expected;
    let payments_len = u64::try_from(payments.len()).unwrap();
    let per_payment = diff / payments_len;
    // The above division isn't perfect.
    let mut remainder = diff - (per_payment * payments_len);

    for mut payment in payments.iter_mut() {
      payment.amount = payment.amount.saturating_sub(per_payment + remainder);
      // Only subtract the remainder once.
      remainder = 0;
    }
    let payments = payments.drain(..).filter(|payment| payment.amount != 0).collect::<Vec<_>>();
    // Sanity check this was done properly
    assert_eq!(actual, payments.iter().map(|payment| payment.amount).sum::<u64>());

    self.plans.entry(actual).or_insert(VecDeque::new()).push_back(payments);
  }
}
